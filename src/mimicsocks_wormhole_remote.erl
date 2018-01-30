%@doc        generalized communication channel
%@author    foldl@outlook.com
-module(mimicsocks_wormhole_remote).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2, suspend_mimic/2]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-import(mimicsocks_wormhole_local, [show_sock/1, report_disconn/2, next_id/2]).

% FSM States
-export([
         init/3,
         wait_ivec/3,
         forward/3,
         wait_sending_cmd/3,
         wait_ho_complete/3,
         bad_key/3
        ]).

-record(state,
        {
            send,       % process chain
            send_sink,
            recv,
            recv_sink,
            recv_inband,
            send_inband,

            rsock,      % remote socket
            rsock2,     % handover socket
            key,
            ivec,
            ho_id,

            up_stream,

            cmd_ref,
            buff = <<>>
        }
       ).

start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

socket_ready(Pid, LSock) when is_pid(Pid), is_port(LSock) ->
    gen_tcp:controlling_process(LSock, Pid),
    gen_statem:cast(Pid, {socket_ready, LSock}).

suspend_mimic(Pid, Duration) -> Pid ! {suspend_mimic, Duration}.

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================
init([Upstream, Key]) ->
    {ok, init, #state{up_stream = Upstream, key = Key}}.

callback_mode() ->
    state_functions.

init(cast, {socket_ready, Socket}, State) when is_port(Socket) ->
    ok = (catch inet:setopts(Socket, [{active, true}, {packet, raw}, binary])),
    {next_state, wait_ivec, State#state{rsock = Socket}};
init(info, Msg, StateData) -> handle_info(Msg, init, StateData).

wait_ivec(cast, {local, Bin}, #state{buff = Buff, key = Key} = State) ->
    All = <<Bin/binary, Buff/binary>>,
    case All of 
        <<IVec:?MIMICSOCKS_HELLO_SIZE/binary, ID0:?MIMICSOCKS_HELLO_SIZE/binary, Rem/binary>> ->
            case next_id(Key, IVec) of
                ID0 ->
                    Cipher = crypto:stream_init(aes_ctr, Key, IVec),
                    RecvSink = mimicsocks_inband_recv:start_link([self(), self()]),
                    mimicsocks_inband_recv:set_key(RecvSink, Key),
                    Recv = mimicsocks_crypt:start_link(decrypt, [RecvSink, Cipher]),
                    
                    {ok, SendSink} = mimicsocks_mimic:start_link([self()]),
                    SendCrypt = mimicsocks_crypt:start_link(encrypt, [SendSink, Cipher]),
                    Send = mimicsocks_inband_send:start_link([SendCrypt, self()]),
                    mimicsocks_inband_send:set_key(Send, Key),
                    Recv ! {recv, self(), Rem},

                    HOID = next_id(Key, ID0),
                    mimicsocks_cfg:register_remote(HOID, self()),
                    {next_state, forward, State#state{
                            ivec = IVec,
                            recv = Recv,
                            recv_sink = RecvSink,
                            send = Send,
                            send_sink = SendSink,
                            recv_inband = RecvSink,
                            send_inband = Send,
                            ho_id = HOID
                            }};
                _ -> 
                    create_close_timer(),
                    {next_state, bad_key, State}
            end;
        _ ->
            
            {next_state, wait_ivec, State#state{buff = All}}
    end;
wait_ivec(info, {tcp, _Socket, Bin}, StateData) ->
    wait_ivec(cast, {local, Bin}, StateData);
wait_ivec(info, Msg, StateData) -> handle_info(Msg, wait_ivec, StateData).

forward(info, Msg, StateData) -> handle_info(Msg, forward, StateData).

bad_key(info, {tcp, _Socket, _Bin}, StateData) -> {keep_state, StateData};
bad_key(info, close, StateData) -> {stop, normal, StateData};
bad_key(info, Msg, StateData) -> handle_info(Msg, bad_key, StateData).

wait_sending_cmd(info,{cmd_sent, Ref}, #state{cmd_ref = Ref, send = Send} = State) ->
    Send ! {flush, Ref, self()},
    {keep_state, State};
wait_sending_cmd(info,{flush, Ref, SendSink}, #state{cmd_ref = Ref, send_sink = SendSink,
                                                     send_inband = SendInband} = State) ->
    mimicsocks_inband_send:continue(SendInband),
    {next_state, wait_ho_complete, State};
wait_sending_cmd(info, {tcp, Socket, Bin}, #state{rsock2 = Socket, buff = Buff} = State) ->
    {keep_state, State#state{buff = <<Buff/binary, Bin/binary>>}};
wait_sending_cmd(info, Msg, State) -> handle_info(Msg, wait_sending_cmd, State).

wait_ho_complete(info, {inband, ho_complete}, #state{rsock = Sock1, rsock2 = Sock2,
                                                     recv = Recv, buff = Buff,
                                                     recv_inband = RecvInband,
                                                     send_sink = SendSink} = State) ->
    mimicsocks_inband_recv:tapping(RecvInband, false),
    gen_tcp:close(Sock1),
    mimicsocks_mimic:change(SendSink),
    Recv ! {recv, self(), Buff},
    {next_state, forward, State#state{rsock = Sock2, rsock2 = undefined, buff = <<>>}};
wait_ho_complete(info, {tcp, Socket, Bin}, #state{rsock2 = Socket, buff = Buff} = State) ->
    {keep_state, State#state{buff = <<Buff/binary, Bin/binary>>}};
wait_ho_complete(info, {recv, SendSink, Bin}, #state{send_sink = SendSink,
                                                     rsock2 = Socket} = State) ->
    gen_tcp:send(Socket, Bin),
    {keep_state, State}; 
wait_ho_complete(info, Msg, State) -> handle_info(Msg, wait_ho_complete, State).

handle_info({ho_socket, Socket}, _StateName, #state{send_inband = SendInband, recv_inband = RecvInband,
                                                    ho_id = Id, key = Key} = StateData) ->
    ok = inet:setopts(Socket, [{active, true}]),
    mimicsocks_inband_recv:tapping(RecvInband, true),
    Ref = mimicsocks_inband_send:recv_cmd(SendInband, <<?MIMICSOCKS_INBAND_HO_R2L>>, hold),
    NewId = next_id(Key, Id),
    mimicsocks_cfg:deregister_remote(Id),
    mimicsocks_cfg:register_remote(NewId, self()),
    {next_state, wait_sending_cmd, StateData#state{rsock2 = Socket, cmd_ref = Ref, 
                                                   ho_id = NewId}};
handle_info({inband_cmd, Pid, Cmds}, _StateName, #state{recv_sink = Pid} = State) ->
    parse_cmds(Cmds, self()),
    {keep_state, State};
handle_info({recv, RecvSink, Data}, _StateName, #state{up_stream = Upstream, recv_sink = RecvSink} = State) ->
    Upstream ! {recv, self(), Data},
    {keep_state, State}; 
handle_info({recv, SendSink, Data}, _StateName, #state{rsock = Socket, send_sink = SendSink} = State) ->
    gen_tcp:send(Socket, Data),
    {keep_state, State}; 
handle_info({recv, Upstream, Data}, _StateName, #state{up_stream = Upstream, send = Send} = State) ->
    Send ! {recv, self(), Data},
    {keep_state, State}; 
handle_info({tcp, Socket, Bin}, _StateName, #state{rsock = Socket, recv = Recv} = State) ->
    Recv ! {recv, self(), Bin},
    {keep_state, State};
handle_info({tcp_closed, Socket}, _StateName, #state{rsock = Socket} = StateData) ->
    report_disconn(Socket, "Remote"),
    {stop, normal, StateData};
handle_info({suspend_mimic, Duration}, _StateName, #state{send_sink = SendSink} = State) ->
    mimicsocks_mimic:suspend(SendSink, Duration),
    {keep_state, State};
handle_info({cmd_sent, Ref}, StateName, StateData) ->
    ?WARNING("cmd_sent ~p in state ~p", [Ref, StateName]),
    {keep_state, StateData};
handle_info(Info, StateName, State) ->
    ?ERROR("unexpected ~p in state ~p", [Info, StateName]),
    {keep_state, State}.

terminate(_Reason, _StateName, #state{rsock=RSocket,
                                      recv = Recv,
                                      send = Send,
                                      ho_id = Id}) ->
    (catch gen_tcp:close(RSocket)),
    (catch Recv ! stop),
    (catch Send ! stop), 
    mimicsocks_cfg:deregister_remote(Id),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%---------------
% utils
%---------------
parse_cmds(<<?MIMICSOCKS_INBAND_NOP, _/binary>> = _Cmds, _Pid) -> ok;
parse_cmds(<<?MIMICSOCKS_INBAND_HO_L2R, Port:16/big, Rem/binary>> = _Cmds, Pid) ->
    Pid ! {inband, start_ho, Port},
    parse_cmds(Rem, Pid);
parse_cmds(<<?MIMICSOCKS_INBAND_HO_COMPLETE_L2R, Rem/binary>> = _Cmds, Pid) ->
    Pid ! {inband, ho_complete},
    parse_cmds(Rem, Pid).

-ifdef(debug).
create_close_timer() -> timer:send_after(100, close).
-else.
create_close_timer() -> timer:send_after((rand:uniform(50) + 1) * 60 * 1000, close).
-endif.