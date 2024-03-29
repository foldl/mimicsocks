%doc    aggregated communication
%author foldl
-module(mimicsocks_local_agg).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

%% API
-export([start_link/1, stop/1, accept/2, accept2/2, socket_ready/2]).
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-import(mimicsocks_wormhole_local, [show_sock/1]).

% FSM States
-export([
         init/3,
         forward/3
        ]).

% utils
-export([parse_full/2, send_data/3]).

start_link(Args) ->
   gen_statem:start_link(?MODULE, Args, []).

accept(Pid, Socket) ->
    ok = gen_tcp:controlling_process(Socket, Pid),
    Pid ! {accept, Socket}.

accept2(Pid, Socket) ->
    ok = gen_tcp:controlling_process(Socket, Pid),
    Pid ! {accept2, Socket}.

socket_ready(Pid, LSock) when is_pid(Pid), is_port(LSock) ->
    gen_tcp:controlling_process(LSock, Pid),
    gen_statem:cast(Pid, {socket_ready, LSock}).

stop(Pid) -> gen_statem:stop(Pid).

callback_mode() ->
    state_functions.

-record(state,
        {
            channel,
            wormhole,
            t_s2i,
            t_i2s,
            last_id = -1,
            key,
            last_timer = undefined,

            buf = <<>>
        }
       ).

%% callback funcitons
init([Key]) ->
    case init_wormhole_remote(Key) of
        {ok, Channel} ->
            {ok, init, #state{wormhole = mimicsocks_wormhole_remote,
                              t_i2s = ets:new(tablei2s, []),
                              t_s2i = ets:new(tables2i, []),
                              key = Key,
                              channel = Channel}};
        {error, Reason} -> {stop, Reason}
    end;
init(Args) ->
    case mimicsocks_wormhole_local:start_link([self() | Args]) of
        {ok, Channel} ->
            {ok, init, #state{channel = Channel,
                      wormhole = mimicsocks_wormhole_local,
                      t_i2s = ets:new(tablei2s, []),
                      t_s2i = ets:new(tables2i, [])
                      }};
        {error, Reason} -> {stop, Reason}
    end.

init(info, {accept2, Socket}, #state{channel = Channel} = State) ->
    mimicsocks_wormhole_remote:socket_ready(Channel, Socket),
    {next_state, forward, State};
init(info, Msg, StateData) -> handle_info(Msg, init, StateData).

forward(info, Info, State) -> handle_info(Info, forward, State).

% here, we use monitor but not fail-restart, because on some VPS,
% gen_tcp:listen fails during restart.
handle_info({'DOWN', _Ref, process, Channel, _Reason}, _StateName,
            #state{channel = Channel, key = Key} = State) ->
    % clean-up
    clean_up(State),

    % re-initialize
    case init_wormhole_remote(Key) of
        {ok, NewChannel} ->
            {next_state, init, State#state{channel = NewChannel, buf = <<>>}};
        {error, Reason} -> {stop, Reason}
    end;
handle_info({accept2, Socket}, _StateName, #state{key = Key,
                                                 wormhole = mimicsocks_wormhole_remote} = State) ->
    % clean-up
    clean_up(State),

    % re-initialize
    case init_wormhole_remote(Key) of
        {ok, NewChannel} ->
            mimicsocks_wormhole_remote:socket_ready(NewChannel, Socket),
            {next_state, forward, State#state{channel = NewChannel, buf = <<>>}};
        {error, Reason} -> {stop, Reason}
    end;
handle_info({accept, Socket}, _StateName, #state{t_i2s = Ti2s, t_s2i = Ts2i,
                                                 channel = Channel, wormhole = W,
                                                 last_id = N,
                                                 last_timer = LastTimer} = State) ->
    State20 = case inet:setopts(Socket, [{active, true}]) of
        ok ->
            Port = make_id(Ti2s, N, N),
            ets:insert(Ti2s, {Port, Socket}),
            ets:insert(Ts2i, {Socket, Port}),
            W:suspend_mimic(Channel, 5000),
            W:recv(Channel, <<?AGG_CMD_NEW_SOCKET, Port:16/big>>),
            State#state{last_id = Port, last_timer = update_ho_timer(LastTimer)};
        _Error ->
            gen_tcp:close(Socket),
            State
    end,
    {keep_state, State20};
handle_info({tcp, Socket, Bin}, _StateName, #state{t_s2i = Ts2i, channel = Channel} = State) ->
    case ets:lookup(Ts2i, Socket) of
        [{Socket, Id}] ->
            send_data(Channel, Id, Bin);
        _ -> ?ERROR("socket (~p) not in db", [show_sock(Socket)])
    end,
    {keep_state, State};
handle_info({tcp_closed, Socket}, _StateName, #state{t_s2i = Ts2i, t_i2s = Ti2s, channel = Channel} = State) ->
    case ets:lookup(Ts2i, Socket) of
        [{Socket, ID}] ->
            Channel ! {recv, self(), <<?AGG_CMD_CLOSE_SOCKET, ID:16/big>>},
            ets:match_delete(Ts2i, {Socket, '_'}),
            ets:match_delete(Ti2s, {ID, '_'});
        _ -> ok
    end,
    {keep_state, State};
handle_info({recv, Channel, Bin}, _StateName, #state{channel = Channel, buf = Buf} = State) ->
    All = <<Buf/binary, Bin/binary>>,
    {ok, Frames, Rem} = parse_full(All, []),
    State10 = lists:foldl(fun handle_cmd/2, State, Frames),
    NewState = State10#state{buf = Rem},
    {keep_state, NewState};
handle_info({tcp_error, Socket, _Reason}, _StateName, #state{t_s2i = Ts2i, t_i2s = Ti2s, channel = Channel} = State) ->
    case ets:lookup(Ts2i, Socket) of
        [{Socket, ID}] ->
            Channel ! {recv, self(), <<?AGG_CMD_CLOSE_SOCKET, ID:16/big>>},
            ets:match_delete(Ts2i, {Socket, '_'}),
            ets:match_delete(Ti2s, {ID, '_'});
        _ -> ok
    end,
    {keep_state, State};
handle_info(ho_timer, _StateName, #state{channel = Channel, wormhole = W} = State) ->
    W:handover_now(Channel),
    {keep_state, State#state{last_timer = undefined}};
handle_info(stop, _StateName, State) ->
    {stop, normal, State};
handle_info(Info, _StateName, State) ->
    ?WARNING("unexpected msg: ~p", [Info]),
    {keep_state, State}.

terminate(_Reason, _StateName, #state{channel = Channel, t_i2s = T1, t_s2i = T2, wormhole = W} =
            _State) ->
    (catch W:stop(Channel)),
    (catch ets:delete(T1)),
    (catch ets:delete(T2)),
    normal.

code_change(_OldVsn, OldStateName, OldStateData, _Extra) ->
    {ok, OldStateName, OldStateData}.

%helpers
clean_up(#state{t_i2s = Ti2s, t_s2i = Ts2i,
                    channel = Channel,
                    wormhole = mimicsocks_wormhole_remote} = _State) ->
    (catch mimicsocks_wormhole_remote:stop(Channel)),
    (catch ets:delete_all_objects(Ti2s)),
    (catch ets:delete_all_objects(Ts2i)).

init_wormhole_remote(Key) ->
    case mimicsocks_wormhole_remote:start_link([self(), Key]) of
        {ok, Channel} ->
            unlink(Channel),
            erlang:monitor(process, Channel),
            {ok, Channel};
        {error, Reason} -> {stop, Reason}
    end.

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
handle_cmd({?AGG_CMD_DATA, Id, Data}, #state{t_i2s = Ti2s, last_timer = LastTimer} = State) ->
    case ets:lookup(Ti2s, Id) of
        [{Id, Socket}] ->
            gen_tcp:send(Socket, Data);
        _ -> ok
    end,
    State#state{last_timer = cancel_timer(LastTimer)}.

make_id(Ti2s, N1, N0) ->
    N2 = (N1 + 1) rem 65536,
    true = (N2 =/= N0),
    case ets:lookup(Ti2s, N2) of
        [{_ID, _Socket}] ->
            make_id(Ti2s, N2, N0);
        _ ->
            N2
    end.

update_ho_timer(undefined) ->
    {ok, TRef} = timer:send_after((rand:uniform(10) + 10) * 1000, ho_timer),
    TRef;
update_ho_timer(Old) ->
    cancel_timer(Old),
    update_ho_timer(undefined).

cancel_timer(undefined) -> undefined;
cancel_timer(Old) ->
    timer:cancel(Old),
    undefined.