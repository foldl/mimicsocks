%doc    aggregated communication
%author foldl@outlook.com
-module(mimicsocks_local_agg).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

%% API
-export([start_link/1, stop/0, accept/1]).
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

% FSM States
-export([
         forward/3,
         ho_initiated/3,
         ho_wait_r2l/3,
         ho_sending_complete/3,
         ho_wait_close/3
        ]).

% utils
-import(mimicsocks_local, [create_ho_timer/1, show_sock/1, report_disconn/2, parse_cmds/2]).
-import(mimicsocks_mimic, [choice/1]).

-export([parse_full/2, send_data/3]).

start_link(Args) ->
   gen_statem:start_link({local, ?MODULE}, ?MODULE, Args, []).

accept(Socket) ->
    ok = gen_tcp:controlling_process(Socket, whereis(?MODULE)),
    ?MODULE ! {accept, Socket}.

stop() -> gen_statem:stop(?MODULE).

callback_mode() ->
    state_functions.

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

            rsock,      % remote socket
            rsock2,     % handover socket
            key,
            ivec,

            cmd_ref,
            ho_timer,
            ho_buf = <<>>,

            t_s2i,
            t_i2s,

            buf = <<>>
        }
       ).

-define(REMOTE_TCP_OPTS, [{active, true}, {packet, raw}, binary, {reuseaddr, true}, {keepalive, true}]).

%% callback funcitons
init([ServerAddr, ServerPort, OtherPorts, Key]) ->
    process_flag(trap_exit, true),
    IVec = crypto:strong_rand_bytes(?MIMICSOCKS_HELLO_SIZE),
    Cipher = crypto:stream_init(aes_ctr, Key, IVec),
    {IdCipher, HOID} = crypto:stream_encrypt(crypto:stream_init(aes_ctr, Key, IVec), IVec),

    RecvSink = mimicsocks_inband_recv:start_link([self(), self()]),
    mimicsocks_inband_recv:set_key(RecvSink, Key),
    Recv = mimicsocks_crypt:start_link(decrypt, [RecvSink, Cipher]),
    
    {ok, SendSink} = mimicsocks_mimic:start_link([self(), identity, identity, iir]),
    SendEncrypt = mimicsocks_crypt:start_link(encrypt, [SendSink, Cipher]),
    Send = mimicsocks_inband_send:start_link([SendEncrypt, self()]),
    mimicsocks_inband_send:set_key(Send, Key),

    case gen_tcp:connect(ServerAddr, ServerPort, ?REMOTE_TCP_OPTS) of
        {ok, RSocket} ->
            ?INFO("Connected to remote ~p:~p for proxying\n", 
                  [ServerAddr, ServerPort]),
            gen_tcp:send(RSocket, IVec),
            {ok, HOTimer} = create_ho_timer(OtherPorts),
            {ok, forward, #state{addr = ServerAddr,
                      port = ServerPort,
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
                      ho_id = HOID,
                      id_cipher = IdCipher,
                      t_i2s = ets:new(tablei2s, []),
                      t_s2i = ets:new(tables2i, [])
                      }};
        {error, Reason} ->
            ?ERROR("can't connect to remote: ~p\n", [Reason]),
            {stop, Reason}
    end.

forward(info, Info, State) -> handle_info(Info, forward, State).

ho_initiated(info, {ho_socket, ok, RSock2}, #state{
                             ho_id = Id, id_cipher = Cipher} = StateData) ->
    ?INFO("ho_initiated", []),
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

handle_info(ho_timer, _StateName, #state{addr = Addr, recv_inband = RecvInband,
                             other_ports = OtherPorts} = StateData) ->
    ?INFO("ho_timer", []),
    Port = choice(OtherPorts),
    mimicsocks_inband_recv:tapping(RecvInband, true),
    Pid = self(),
    spawn(fun () ->
        case gen_tcp:connect(Addr, Port, ?REMOTE_TCP_OPTS, 3000) of
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
handle_info({accept, Socket}, _StateName, #state{send = Send, t_i2s = Ti2s, t_s2i = Ts2i,
                                                 send_sink = SendSink} = State) ->
    case {inet:setopts(Socket, [{active, true}]), inet:peername(Socket)} of
        {ok, {ok, {_Addr, Port}}} ->
            ets:insert(Ti2s, {Port, Socket}),
            ets:insert(Ts2i, {Socket, Port}),
            mimicsocks_mimic:suspend(SendSink, 5000),
            Send ! {recv, self(), <<?AGG_CMD_NEW_SOCKET, Port:16/big>>};
        Error -> 
            ?ERROR("can't get port ~p~n", [Error]),
            gen_tcp:close(Socket)
    end,
    {keep_state, State};
handle_info({tcp, RSocket, Bin}, _StateName, #state{rsock = RSocket, recv = Recv} = State) ->
    Recv ! {recv, self(), Bin},
    {keep_state, State};
handle_info({tcp, Socket, Bin}, _StateName, #state{t_s2i = Ts2i, send = Send} = State) ->
    case ets:lookup(Ts2i, Socket) of
        [{Socket, Id}] -> 
            send_data(Send, Id, Bin);
        _ -> ?ERROR("socket (~s) not is db", [show_sock(Socket)])
    end,
    {keep_state, State};
handle_info({tcp_closed, RSocket}, _StateName, #state{rsock = RSocket} = State) ->
    {stop, normal, State};
handle_info({tcp_closed, Socket}, _StateName, #state{t_s2i = Ts2i, t_i2s = Ti2s, send = Send} = State) ->
    case ets:lookup(Ts2i, Socket) of
        [{Socket, ID}] -> 
            Send ! {recv, self(), <<?AGG_CMD_CLOSE_SOCKET, ID:16/big>>},
            ets:match_delete(Ts2i, {Socket, '_'}),
            ets:match_delete(Ti2s, {ID, '_'});
        _ -> ok
    end,
    {keep_state, State};
handle_info({recv, SendSink, Bin}, _StateName, #state{send_sink = SendSink, rsock = Socket} = State) ->
    gen_tcp:send(Socket, Bin),    
    {keep_state, State};
handle_info({recv, RecvSink, Bin}, _StateName, #state{recv_sink = RecvSink, buf = Buf} = State) ->
    All = <<Buf/binary, Bin/binary>>,
    {ok, Frames, Rem} = parse_full(All, []),
    State10 = lists:foldl(fun handle_cmd/2, State, Frames),
    NewState = State10#state{buf = Rem},
    {keep_state, NewState};
handle_info(stop, _StateName, State) -> 
    {stop, normal, State};
handle_info(Info, _StateName, State) ->
    ?WARNING("unexpected msg: ~p", [Info]),
    {keep_state, State}.

terminate(_Reason, _StateName, #state{rsock = Sock1, rsock2 = Sock2, t_i2s = T1, t_s2i = T2} =
            _State) ->
    (catch gen_tcp:close(Sock1)),
    (catch gen_tcp:close(Sock2)),
    (catch ets:delete(T1)),
    (catch ets:delete(T2)),
    normal.

code_change(_OldVsn, OldStateName, OldStateData, _Extra) ->
    {ok, OldStateName, OldStateData}.

%helpers
send_data(Send, Id, List) when is_list(List) ->
    lists:foreach(fun (X) -> send_data(Send, Id, X) end, List);
send_data(_Send, _Id, <<>>) -> ok;
send_data(Send, Id, Bin) when size(Bin) < 256 ->
    Len = size(Bin),
    Send ! {recv, self(), <<?AGG_CMD_SMALL_DATA, Id:16/big, Len, Bin/binary>>};
send_data(Send, Id, Bin) when size(Bin) < 65536 ->
    Len = size(Bin),
    Send ! {recv, self(), <<?AGG_CMD_DATA, Id:16/big, Len:16/big, Bin/binary>>};
send_data(Send, Id, Bin) ->
    <<This:65535/binary, Rem/binary>> = Bin,
    Send ! {recv, self(), <<?AGG_CMD_DATA, Id:16/big, 65535:16/big, This/binary>>},
    send_data(Send, Id, Rem).

parse_data(<<>>) -> incomplete;
parse_data(<<?AGG_CMD_NOP, Rem/binary>>) ->
    case Rem of
        <<_Reserved:16/big, Len, _Dummy:Len/binary, Rem10/binary>> ->
            {?AGG_CMD_NOP, Rem10};
        _ -> incomplete
    end;
parse_data(<<?AGG_CMD_NEW_SOCKET, Rem/binary>>) ->
    case Rem of
        <<Id:16/big, Rem10/binary>> ->
            {{?AGG_CMD_NEW_SOCKET, Id}, Rem10};
        _ -> incomplete
    end;
parse_data(<<?AGG_CMD_CLOSE_SOCKET, Rem/binary>>) ->
    case Rem of
        <<Id:16/big, Rem10/binary>> ->
            {{?AGG_CMD_CLOSE_SOCKET, Id}, Rem10};
        _ -> incomplete
    end;
parse_data(<<?AGG_CMD_DATA, Rem/binary>>) ->
    case Rem of
        <<Id:16/big, Len:16/big, Data:Len/binary, Rem10/binary>> ->
            {{?AGG_CMD_DATA, Id, Data}, Rem10};
        _ -> incomplete
    end;
parse_data(<<?AGG_CMD_SMALL_DATA, Rem/binary>>) ->
    case Rem of
        <<Id:16/big, Len, Data:Len/binary, Rem10/binary>> ->
            {{?AGG_CMD_DATA, Id, Data}, Rem10};
        _ -> incomplete
    end;
parse_data(<<Cmd, _/binary>>) ->
    {bad_command, Cmd}.

parse_full(Data, Acc) ->
    case parse_data(Data) of
        incomplete -> {ok, lists:reverse(Acc), Data};
        {bad_command, Value} -> {{bad_command, Value}, Acc, Data};
        {Frame, Rem} -> parse_full(Rem, [Frame | Acc])
    end.

handle_cmd(?AGG_CMD_NOP, State) -> State;
handle_cmd({?AGG_CMD_NEW_SOCKET, _Id}, State) ->
    ?ERROR("unexpected ?AGG_CMD_NEW_SOCKET", []),
    State;
handle_cmd({?AGG_CMD_CLOSE_SOCKET, Id}, #state{t_s2i = Ts2i, t_i2s = Ti2s} = State) ->
    case ets:lookup(Ti2s, Id) of
        [{ID, Socket}] -> 
            ets:match_delete(Ts2i, {Socket, '_'}),
            ets:match_delete(Ti2s, {ID, '_'});
        _ -> ok
    end,
    State;
handle_cmd({?AGG_CMD_DATA, Id, Data}, #state{t_i2s = Ti2s, send = Send} = State) ->
    case ets:lookup(Ti2s, Id) of
        [{Id, Socket}] -> 
            gen_tcp:send(Socket, Data);
        _ -> ok
    end,
    State.