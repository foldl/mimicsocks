%@doc    generalized communication channel
%@author foldl@outlook.com
-module(mimicsocks_wormhole_local).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

%% API
-export([start_link/1, stop/1, recv/2, suspend_mimic/2]).
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-export([report_disconn/2, show_sock/1, next_id/2]).

% FSM States
-export([
         forward/3,
         ho_initiated/3,
         ho_wait_r2l/3,
         ho_sending_complete/3,
         ho_wait_close/3
        ]).

% utils
-import(mimicsocks_mimic, [choice/1]).

start_link(Args) ->
   gen_statem:start_link(?MODULE, Args, []).

stop(Pid) -> gen_statem:stop(Pid).

recv(Pid, Data) -> Pid ! {recv, self(), Data}.

suspend_mimic(Pid, Duration) -> Pid ! {suspend_mimic, Duration}.

callback_mode() ->
    state_functions.

-record(state,
        {
            up_stream,     % data receiver

            addr,       % remote addr & port
            port,
            other_ports = [], % ports for handover
            extra_args,

            send,       % process chain
            send_sink,
            recv,
            recv_sink,
            recv_inband,
            send_inband,

            ho_id,

            rsock,      % remote socket
            rsock2,     % handover socket
            key,
            ivec,

            cmd_ref,
            ho_timer,
            ho_buf = <<>>,

            ping_timer
        }
       ).

%% callback funcitons
init([UpStream, ServerAddr, ServerPort, OtherPorts, Key | T]) ->
    process_flag(trap_exit, true),
    IVec = gen_ivec(),
    ID0 = next_id(Key, IVec),
    HOID = next_id(Key, ID0),

    RecvSink = mimicsocks_inband_recv:start_link([self(), self()]),
    mimicsocks_inband_recv:set_key(RecvSink, Key),
    Recv = mimicsocks_crypt:start_link(decrypt, [RecvSink, mimicsocks_crypt:init_aes_ctr_dec(Key, IVec)]),

    {ok, SendSink} = mimicsocks_mimic:start_link([self(), identity, identity, iir]),
    SendEncrypt = mimicsocks_crypt:start_link(encrypt, [SendSink, mimicsocks_crypt:init_aes_ctr_enc(Key, IVec)]),
    Send = mimicsocks_inband_send:start_link([SendEncrypt, self()]),
    mimicsocks_inband_send:set_key(Send, Key),

    case connect(ServerAddr, ServerPort, T) of
        {ok, RSocket} ->
            ?INFO("Connected to remote ~p:~p\n", [ServerAddr, ServerPort]),
            gen_tcp:send(RSocket, <<IVec/binary, ID0/binary>>),
            {ok, HOTimer} = create_ho_timer(OtherPorts),
            {ok, forward, #state{
                      up_stream = UpStream,
                      addr = ServerAddr,
                      port = ServerPort,
                      extra_args = T,
                      other_ports = OtherPorts,
                      key = Key,
                      rsock = RSocket,
                      ivec = IVec,
                      recv = Recv,
                      recv_sink = RecvSink,
                      send = Send,
                      send_sink = SendSink,
                      send_inband = Send,
                      recv_inband = RecvSink,
                      ho_timer = HOTimer,
                      ho_id = HOID
                      }};
        {error, Reason} ->
            ?ERROR("can't connect to remote: ~p~n", [Reason]),
            {stop, Reason}
    end.

forward(info, Info, State) -> handle_info(Info, forward, State).

ho_initiated(info, {ho_socket, ok, RSock2}, #state{
                             ho_id = Id, recv_inband = RecvInband, key = Key} = StateData) ->
    ?INFO("ho_initiated", []),
    mimicsocks_inband_recv:tapping(RecvInband, true),
    gen_tcp:send(RSock2, Id),
    {next_state, ho_wait_r2l,
                 StateData#state{rsock2 = RSock2, ho_buf = <<>>, ho_id = next_id(Key, Id)},
                 [{state_timeout, 3000, ho_wait_r2l}]};
ho_initiated(info, {ho_socket, error, Reason}, #state{recv_inband = RecvInband} = StateData) ->
    ?WARNING("ho_initiated failed with reason ~p", [Reason]),
    mimicsocks_inband_recv:tapping(RecvInband, false),
    {next_state, forward, StateData};
ho_initiated(info, Msg, Data) -> handle_info(Msg, ho_initiated, Data).

ho_wait_r2l(state_timeout, _, StateData) ->
    {stop, {ho_wait_r2l, state_timeout}, StateData#state{ho_buf = <<"... truncated ...">>}};
ho_wait_r2l(info, {inband, ho_r2l}, #state{recv = Recv, ho_buf = Buf,
                                               send_inband = SendInband,
                                               recv_inband = RecvInband} = StateData) ->
    Ref = mimicsocks_inband_send:recv_cmd(SendInband, <<?MIMICSOCKS_INBAND_HO_COMPLETE_L2R>>, hold),
    mimicsocks_inband_recv:tapping(RecvInband, false),
    Recv ! {recv, self(), Buf},
    {next_state, ho_sending_complete, StateData#state{cmd_ref = Ref, ho_buf = <<>>}};
ho_wait_r2l(info, {tcp, Socket, Bin}, #state{rsock2 = Socket, ho_buf = Buf} = StateData) ->
    {keep_state, StateData#state{ho_buf = <<Buf/binary, Bin/binary>>}};
ho_wait_r2l(info, Msg, Data) -> handle_info(Msg, ho_wait_r2l, Data).

ho_sending_complete(info, {cmd_sent, Ref}, #state{send = Send} = StateData) ->
    Send ! {flush, Ref, self()},
    {next_state, ho_sending_complete, StateData};
ho_sending_complete(info, {flush, Ref, SendSink}, #state{rsock2 = Socket2, send_sink = SendSink,
                                                         rsock = Socket1, cmd_ref = Ref,
                                                         send_inband = SendInband} = StateData) ->
    mimicsocks_inband_send:continue(SendInband),
    {next_state, ho_wait_close, StateData#state{rsock = Socket2, rsock2 = Socket1}};
ho_sending_complete(info, {tcp, Socket, Bin}, #state{rsock2 = Socket, recv = Recv} = StateData) ->
    Recv ! {recv, self(), Bin},
    {keep_state, StateData};
ho_sending_complete(info, Msg, Data) -> handle_info(Msg, ho_sending_complete, Data).

ho_wait_close(info, {tcp_closed, Socket}, #state{rsock2 = Socket, other_ports = OtherPorts,
                                                 send_sink = SendSink} = StateData) ->
    ?INFO("ho complete", []),
    mimicsocks_mimic:change(SendSink),
    {ok, HOTimer} = create_ho_timer(OtherPorts),
    {next_state, forward, StateData#state{rsock2 = undefined, ho_timer = HOTimer}};
ho_wait_close(info, {recv, SendSink, Bin}, #state{rsock2 = Socket, send_sink = SendSink} = StateData) ->
    gen_tcp:send(Socket, Bin),
    {keep_state, StateData};
ho_wait_close(info, {tcp, Socket, Bin}, #state{rsock2 = Socket, recv = Recv} = StateData) ->
    Recv ! {recv, self(), Bin},
    {keep_state, StateData};
ho_wait_close(info, Msg, Data) -> handle_info(Msg, ho_wait_close, Data).

handle_info(ho_timer, _StateName, #state{addr = Addr, other_ports = OtherPorts, extra_args = Extra} = StateData) ->
    ?INFO("ho_timer", []),
    Port = choice(OtherPorts),
    Pid = self(),
    spawn(fun () ->
        case connect(Addr, Port, Extra) of
            {ok, RSocket} ->
                gen_tcp:controlling_process(RSocket, Pid),
                Pid ! {ho_socket, ok, RSocket};
            {error, Reason} ->
                Pid ! {ho_socket, error, Reason}
        end end),
    {next_state, ho_initiated, StateData#state{ho_timer = undefined}};
handle_info({inband_cmd, Pid, Cmds}, _StateName, #state{recv_inband = Pid} = StateData) ->
    parse_cmds(Cmds, self()),
    {keep_state, StateData};
handle_info({tcp, RSocket, Bin}, _StateName, #state{rsock = RSocket, recv = Recv} = State) ->
    Recv ! {recv, self(), Bin},
    {keep_state, State};
handle_info({tcp_closed, RSocket}, _StateName, #state{rsock = RSocket} = State) ->
    {stop, remote_down, State};
handle_info({recv, SendSink, Bin}, _StateName, #state{send_sink = SendSink, rsock = Socket} = State) ->
    gen_tcp:send(Socket, Bin),
    {keep_state, State};
handle_info({recv, Output, Bin}, _StateName, #state{send = Send, up_stream = Output} = State) ->
    Send ! {recv, self(), Bin},
    {keep_state, State};
handle_info({recv, RecvSink, Bin}, _StateName, #state{recv_sink = RecvSink, up_stream = Output} = State) ->
    Output ! {recv, self(), Bin},
    {keep_state, State};
handle_info({suspend_mimic, Duration}, _StateName, #state{send_sink = SendSink} = State) ->
    mimicsocks_mimic:suspend(SendSink, Duration),
    {keep_state, State};
handle_info(stop, _StateName, State) ->
    {stop, normal, State};
handle_info(Info, _StateName, State) ->
    ?WARNING("unexpected msg: ~p", [Info]),
    {keep_state, State}.

terminate(_Reason, _StateName, #state{rsock = Sock1, rsock2 = Sock2} =
            _State) ->
    (catch gen_tcp:close(Sock1)),
    (catch gen_tcp:close(Sock2)),
    normal.

code_change(_OldVsn, OldStateName, OldStateData, _Extra) ->
    {ok, OldStateName, OldStateData}.

%---------------
% utils
%---------------

-ifdef(debug).
create_ho_timer(Ports) ->
    case length(Ports) > 0 of
        true -> timer:send_after(5 * 1000, ho_timer);
        _ -> {ok, undefined}
    end.
-else.
create_ho_timer(Ports) ->
    case length(Ports) > 0 of
        true -> timer:send_after((rand:uniform(10) + 20) * 60 * 1000, ho_timer);
        _ -> {ok, undefined}
    end.
-endif.

report_disconn(Socket, Type) ->
    case inet:peername(Socket) of
        {ok, {Addr, Port}} ->
            ?INFO("~p ~p disconnected (port ~p).", [Type, Addr, Port]);
        {error, _} ->
            ?INFO("~p disconnected", [Type])
    end.

show_sock(Socket) ->
    {ok, {Addr, Port}} = inet:peername(Socket),
    {Addr, Port}.

parse_cmds(<<?MIMICSOCKS_INBAND_NOP, _/binary>> = _Cmds, _Pid) -> ok;
parse_cmds(<<?MIMICSOCKS_INBAND_HO_R2L, Rem/binary>> = _Cmds, Pid) ->
    Pid ! {inband, ho_r2l},
    parse_cmds(Rem, Pid);
parse_cmds(<<?MIMICSOCKS_INBAND_HO_COMPLETE_R2L, Rem/binary>> = _Cmds, Pid) ->
    Pid ! {inband, ho_complete},
    parse_cmds(Rem, Pid).

-define(REMOTE_TCP_OPTS, [{packet, raw}, binary, {reuseaddr, true}, {keepalive, true},
                          {send_timeout, 3000}, {send_timeout_close, true}]).

connect(ServerAddr, ServerPort, [{http_proxy, ProxyAddr, ProxyPort}]) ->
    case gen_tcp:connect(ProxyAddr, ProxyPort, [{active, false} | ?REMOTE_TCP_OPTS]) of
        {ok, Socket} ->
            Req = ["CONNECT ", ip_to_list(ServerAddr), ":", integer_to_list(ServerPort), " HTTP/1.1\r\n\r\n"],
            gen_tcp:send(Socket, Req),
            case wait_result(Socket) of
                {ok, <<>>} ->
                    inet:setopts(Socket, [{active, true}]),
                    {ok, Socket};
                {ok, Remain} ->
                    self() ! {tcp, Socket, Remain},
                    inet:setopts(Socket, [{active, true}]),
                    {ok, Socket};
                OtherError ->
                    ?ERROR("~p~n", [OtherError]),
                    gen_tcp:close(Socket),
                    OtherError
            end;
        Result -> Result
    end;
connect(ServerAddr, ServerPort, _) ->
    gen_tcp:connect(ServerAddr, ServerPort, [{active, true} | ?REMOTE_TCP_OPTS]).

ip_to_list(X) when is_list(X) -> X;
ip_to_list({A,B,C,D}) ->
    io_lib:format("~B.~B.~B.~B",[A,B,C,D]);
ip_to_list({A,B,C,D,E,F,G,H}) ->
    io_lib:format("~.16B.~.16B.~.16B.~.16B.~.16B.~.16B.~.16B.~.16B",[A,B,C,D,E,F,G,H]).

wait_line(_Socket, _Acc, N) when N < 0 -> {error, timeout};
wait_line(Socket, Acc, N) ->
    receive
    after 50 -> ok
    end,
    case gen_tcp:recv(Socket, 0) of
        {ok, Data} ->
            All = <<Acc/binary, Data/binary>>,
            case binary:split(All, <<"\r\n\r\n">>) of
                [_, Remain] -> {ok, Remain};
                [_] -> wait_line(Socket, All, N - 1)
            end;
        X -> X
    end.

wait_result(Socket) ->
    Expected = <<"HTTP/1.1 200">>,
    case gen_tcp:recv(Socket, size(Expected), 2000) of
        {ok, Expected} -> wait_line(Socket, <<>>, 40);
        {ok, <<"HTTP/1.0 200">>} -> wait_line(Socket, <<>>, 40);
        {ok, Other} -> {error, Other};
        X -> X
    end.

next_id(Key, ID) -> mimicsocks_crypt:hmac_sha(Key, ID, ?MIMICSOCKS_HELLO_SIZE).

%@doc generate a IVEC using random algo in order to randomized entropy on IVEC
gen_ivec() ->
    L = lists:seq(1, ?MIMICSOCKS_HELLO_SIZE),
    T = rand:uniform(256) - 1,
    case rand:uniform(3) of
        1 -> crypto:strong_rand_bytes(?MIMICSOCKS_HELLO_SIZE);
        _ ->
            Q = 256 div rand:uniform(10),
            list_to_binary([(rand:uniform(Q) + T) rem 256 || _ <- L])
    end.
