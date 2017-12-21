%@doc       local socket forwarding node
%           local traffic is forwarded and handled by remote node
%@author    foldl@outlook.com
-module(mimicsocks_local).

-include_lib("mimicsocks/include/mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

% utils
-export([report_disconn/2, show_sock/1, choice/1]).

% FSM States
-export([
         init/3,
         forward/3,
         ho_initiated/3,
         ho_wait_r2l/3,
         ho_sending_complete/3,
         ho_wait_close/3
        ]).

-record(state,
        {
            addr,       % remote addr & port
            port,
            other_ports = [], % ports for handover

            send,       % process chain
            send_sink,
            recv,
            recv_sink,
            recv_inband,
            send_inband,

            ho_id,
            id_cipher,

            lsock,      % local socket
            rsock,      % remote socket
            rsock2,     % handover socket
            key,
            ivec,

            cmd_ref,
            ho_timer,
            ho_buf = <<>>
        }
       ).

-define(REMOTE_TCP_OPTS, [{active, true}, {packet, raw}, binary, {reuseaddr, true}]).

start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

socket_ready(Pid, LSock) when is_pid(Pid), is_port(LSock) ->
    gen_tcp:controlling_process(LSock, Pid),
    gen_statem:cast(Pid, {socket_ready, LSock}).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================
init([ServerAddr, ServerPort, OtherPorts, Key]) ->
    process_flag(trap_exit, true),
    IVec = crypto:strong_rand_bytes(?MIMICSOCKS_HELLO_SIZE),
    Cipher = crypto:stream_init(aes_ctr, Key, IVec),
    {IdCipher, HOID} = crypto:stream_encrypt(crypto:stream_init(aes_ctr, Key, IVec), IVec),

    RecvSink = mimicsocks_inband_recv:start_link([self(), self()]),
    mimicsocks_inband_recv:set_key(RecvSink, Key),
    Recv = mimicsocks_crypt:start_link(decrypt, [RecvSink, Cipher]),
    
    {ok, SendSink} = mimicsocks_mimic:start_link([self(), 
                                            choice([identity, uniform, gaussian]),
                                            choice([identity, uniform, gaussian, poission]),
                                            iir]),
    SendEncrypt = mimicsocks_crypt:start_link(encrypt, [SendSink, Cipher]),
    Send = mimicsocks_inband_send:start_link([SendEncrypt, self()]),
    mimicsocks_inband_send:set_key(Send, Key),

    {ok, HOTimer} = create_ho_timer(OtherPorts),
    
    {ok, init, #state{addr = ServerAddr,
                      port = ServerPort,
                      other_ports = OtherPorts,
                      key = Key,
                      ivec = IVec,
                      recv = Recv,
                      recv_sink = RecvSink,
                      send = Send,
                      send_sink = SendSink,
                      send_inband = Send,
                      recv_inband = RecvSink,
                      ho_timer = HOTimer,
                      ho_id = HOID,
                      id_cipher = IdCipher
                      }}.

callback_mode() ->
    state_functions.

init(cast, {socket_ready, Socket}, #state{addr = Addr, port = Port, ivec = IVec} = StateData) when is_port(Socket) ->
    ok = inet:setopts(Socket, [{active, true}, {packet, raw}, binary]),
    case gen_tcp:connect(Addr, Port, ?REMOTE_TCP_OPTS) of
        {ok, RSocket} ->
            ?INFO("Connected to remote ~p:~p for proxying ~p\n", 
                  [Addr, Port, show_sock(Socket)]),
            gen_tcp:send(RSocket, IVec),
            {next_state, forward, 
             StateData#state{lsock = Socket, rsock = RSocket}};
        {error, Reason} ->
            ?ERROR("wait_req can't connect to remote: ~p\n", [Reason]),
            {stop, Reason, StateData}
    end;
init(info, Msg, Data) -> handle_info(Msg, init, Data).

forward(info, Msg, Data) -> handle_info(Msg, forward, Data).

ho_initiated(info, {ho_socket, ok, RSock2}, #state{
                             ho_id = Id, id_cipher = Cipher} = StateData) ->
    gen_tcp:send(RSock2, Id),
    {NewCipherState, NewId} = crypto:stream_encrypt(Cipher, Id),
    {next_state, ho_wait_r2l, StateData#state{rsock2 = RSock2, ho_buf = <<>>, ho_id = NewId, id_cipher = NewCipherState}};
ho_initiated(info, {ho_socket, error, Reason}, #state{recv_inband = RecvInband} = StateData) ->
    ?WARNING("ho_initiated failed with reason ~p", [Reason]),
    mimicsocks_inband_recv:tapping(RecvInband, false),
    {next_state, forward, StateData};
ho_initiated(info, Msg, Data) -> handle_info(Msg, ho_initiated, Data).

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

ho_wait_close(info, {tcp_closed, Socket}, #state{rsock2 = Socket, other_ports = OtherPorts} = StateData) ->
    ?INFO("ho complete", []),
    {ok, HOTimer} = create_ho_timer(OtherPorts),
    {next_state, forward, StateData#state{rsock2 = undefined, ho_timer = HOTimer}};
ho_wait_close(info, {recv, SendSink, Bin}, #state{rsock2 = Socket, send_sink = SendSink} = StateData) ->
    gen_tcp:send(Socket, Bin),
    {keep_state, StateData};
ho_wait_close(info, {tcp, Socket, Bin}, #state{rsock2 = Socket, recv = Recv} = StateData) ->
    Recv ! {recv, self(), Bin},
    {keep_state, StateData};
ho_wait_close(info, Msg, Data) -> handle_info(Msg, ho_wait_close, Data).

handle_info(ho_timer, _StateName, #state{addr = Addr, recv_inband = RecvInband,
                             other_ports = OtherPorts} = StateData) ->
    Port = choice(OtherPorts),
    mimicsocks_inband_recv:tapping(RecvInband, true),
    Pid = self(),
    spawn(fun () ->
        case gen_tcp:connect(Addr, Port, ?REMOTE_TCP_OPTS, 1000) of
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
handle_info({recv, RecvSink, Data}, _StateName, #state{lsock = Socket, recv_sink = RecvSink} = StateData) ->
    gen_tcp:send(Socket, Data),
    {keep_state, StateData}; 
handle_info({recv, SendSink, Data}, _StateName, #state{rsock = Socket, send_sink = SendSink} = StateData) ->
    gen_tcp:send(Socket, Data),
    {keep_state, StateData}; 
handle_info({tcp, Socket, Bin}, _StateName, #state{lsock = Socket, send = Send} = StateData) ->
    mimicsocks_inband_send:recv(Send, Bin),
    {keep_state, StateData};
handle_info({tcp, Socket, Bin}, _StateName, #state{rsock = Socket, recv = Recv} = StateData) ->
    mimicsocks_crypt:recv(Recv, Bin),
    {keep_state, StateData};
handle_info({tcp_closed, Socket}, _StateName, #state{lsock = Socket} = StateData) ->
    report_disconn(Socket, "local"),
    {stop, normal, StateData};
handle_info({tcp_closed, Socket}, _StateName, #state{rsock = Socket} = StateData) ->
    report_disconn(Socket, "remote"),
    {stop, normal, StateData};
handle_info(Info, StateName, StateData) ->
    ?ERROR("unexpected ~p in state ~p", [Info, StateName]),
    {keep_state, StateData}.

terminate(_Reason, _StateName, #state{lsock=LSocket,
                                      rsock=RSocket,
                                      recv = Recv,
                                      send = Send} = _StateData) ->
    (catch gen_tcp:close(LSocket)),
    (catch gen_tcp:close(RSocket)),
    Recv ! stop,
    Send ! stop,
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%---------------
% utils
%---------------

-ifdef(debug).
create_ho_timer(Ports) ->
    case length(Ports) > 0 of
        true -> timer:send_after(5 * 1000, ho_timer);
        _ -> undefined
    end.
-else.
create_ho_timer(Ports) ->
    case length(Ports) > 0 of
        true -> timer:send_after((rand:uniform(300) + 30) * 1000, ho_timer);
        _ -> undefined
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

choice(L) ->
    Len = length(L),
    lists:nth(rand:uniform(Len), L).
