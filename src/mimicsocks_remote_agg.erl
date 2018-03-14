%@doc remote socket forwarding server
%     
%     tcp traffic is either forwarded to a socks5 handler or relayed to another mimicsocks proxy
%@author    foldl@outlook.com
-module(mimicsocks_remote_agg).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-import(mimicsocks_wormhole_local, [show_sock/1, report_disconn/2]).
-import(mimicsocks_local_agg, [parse_full/2, send_data/3]).

% FSM States
-export([
         init/3,
         forward/3,
         closing/3
        ]).

-record(state,
        {
            channel,

            handler_mod,
            handler_args,

            cmd_ref,
            buff = <<>>,
            t_p2i,
            t_i2p,
            d_buf = <<>>
        }
       ).

start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

socket_ready(Pid, LSock) when is_pid(Pid), is_port(LSock) ->
    gen_tcp:controlling_process(LSock, Pid),
    gen_statem:cast(Pid, {socket_ready, LSock}).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================
init([Key, HandlerMod, HandlerArgs]) ->
    case mimicsocks_wormhole_remote:start_link([self(), Key]) of
        {ok, Channel} ->
            erlang:monitor(process, Channel),
            unlink(Channel),
            {ok, init, #state{handler_mod = HandlerMod,
                              handler_args = HandlerArgs,
                              t_i2p = ets:new(tablei2p, []),
                              t_p2i = ets:new(tablep2i, []),
                              channel = Channel}};
        {error, Reason} -> {stop, Reason}
    end.

callback_mode() ->
    state_functions.

init(cast, {socket_ready, Socket}, #state{channel = Channel} = State) when is_port(Socket) ->
    mimicsocks_wormhole_remote:socket_ready(Channel, Socket),
    {next_state, forward, State};
init(info, Msg, StateData) -> handle_info(Msg, init, StateData).

forward(info, Msg, StateData) -> handle_info(Msg, forward, StateData).

closing(cast, _, State) -> {keep_state, State};
closing(info, stop, State) -> {stop, normal, State};
closing(info, _Msg, State) -> {keep_state, State}.

handle_info({recv, Channel, Bin}, _StateName, #state{channel = Channel,
                                                     d_buf = Buf} = State) ->
    All = <<Buf/binary, Bin/binary>>,
    {ok, Frames, Rem} = parse_full(All, []),
    State10 = lists:foldl(fun handle_cmd/2, State, Frames),
    NewState = State10#state{d_buf = Rem},
    {keep_state, NewState};
handle_info({recv, Handler, Data}, _StateName, #state{handler_mod = Mod, channel = Channel, t_p2i = Tp2i} = State) ->
    case ets:lookup(Tp2i, Handler) of
        [{Handler, ID}] -> 
            % traffic control
            case proc_high(Channel) of
                true ->
                    Mod:active(Handler, false),
                    timer:send_after(20, {recv, Handler, ID, Data});
                _ ->
                    send_data(Channel, ID, Data)
            end;
        _ -> ok
    end,
    {keep_state, State}; 
handle_info({recv, Handler, ID, Data} = Msg, _StateName, #state{handler_mod = Mod, channel = Channel} = State) ->
    case proc_low(Channel) of
        true ->
            timer:send_after(20, Msg);
        _ ->
            send_data(Channel, ID, Data),
            Mod:active(Handler, true)
    end,
    {keep_state, State}; 
handle_info({'DOWN', _Ref, process, Channel, _Reason}, _StateName, 
            #state{channel = Channel} = _State) ->
    {stop, normal};
handle_info({'DOWN', _Ref, process, Handler, _Reason}, _StateName, 
            #state{t_i2p = Ti2p, t_p2i = Tp2i} = State) ->
    case ets:lookup(Tp2i, Handler) of
        [{Handler, Id}] -> 
            ets:match_delete(Tp2i, {Handler, '_'}),
            ets:match_delete(Ti2p, {Id, '_'});
        _ -> ok
    end,
    {keep_state, State};
handle_info(Info, StateName, State) ->
    ?ERROR("unexpected ~p in state ~p", [Info, StateName]),
    {keep_state, State}.

terminate(_Reason, _StateName, #state{channel = Channel,
                                      handler_mod = Mod,
                                      t_i2p = Ti2p,
                                      t_p2i = Tp2i}) ->
    (catch mimicsocks_wormhole_remote:stop(Channel)),
    ets:foldl(fun (Pid, _) -> (catch Mod:stop(Pid)) end, 0, Ti2p),
    ets:delete(Ti2p),
    ets:delete(Tp2i),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%---------------
% utils
%---------------

handle_cmd(?AGG_CMD_NOP, State) -> State;
handle_cmd({?AGG_CMD_NEW_SOCKET, Id}, #state{t_p2i = Tp2i, t_i2p = Ti2p,
                                             handler_mod = Module,
                                             handler_args = Args,
                                             channel = Channel} = State) ->
    case ets:lookup(Ti2p, Id) of
        [{Id, Pid}] ->
            ?ERROR("?AGG_CMD_NEW_SOCKET id already exsits, stop it", []),
            (catch Module:stop(Pid));
        _ -> ok
    end,
    mimicsocks_wormhole_remote:suspend_mimic(Channel, 5000),
    {ok, NewPid} = Module:start_link([self() | Args]),
    unlink(NewPid),
    erlang:monitor(process, NewPid),
    ets:insert(Ti2p, {Id, NewPid}),
    ets:insert(Tp2i, {NewPid, Id}),
    State;
handle_cmd({?AGG_CMD_CLOSE_SOCKET, Id}, #state{t_p2i = Tp2i, t_i2p = Ti2p,
                                               handler_mod = Mod} = State) ->
    case ets:lookup(Ti2p, Id) of
        [{Id, Pid}] -> 
            ets:match_delete(Tp2i, {Pid, '_'}),
            ets:match_delete(Ti2p, {Id, '_'}),
            (catch Mod:stop(Pid));
        _ -> ok
    end,
    State;
handle_cmd({?AGG_CMD_DATA, Id, Data}, #state{t_i2p = Ti2p} = State) ->
    case ets:lookup(Ti2p, Id) of
        [{Id, Pid}] -> 
            Pid ! {recv, self(), Data};
        _ -> 
            ?WARNING("invalid port id: ~p", [Id])
    end,
    State.

proc_high(Pid) -> process_info(Pid, message_queue_len) > 8000.
proc_low(Pid) -> process_info(Pid, message_queue_len) < 1000.