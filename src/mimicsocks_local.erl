%@doc       local socket forwarding node
%           local traffic is forwarded and handled by remote node
%@author    foldl@outlook.com
-module(mimicsocks_local).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

% utils
-import(mimicsocks_mimic, [choice/1]).

% FSM States
-export([
         init/3,
         forward/3
        ]).

-record(state,
        {
            channel,
            lsock
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
init(Args) ->
    case mimicsocks_wormhole_local:start_link([self() | Args]) of
        {ok, Channel} ->
            {ok, init, #state{channel = Channel}};
        {error, Reason} -> {stop, Reason}
    end.

callback_mode() ->
    state_functions.

init(cast, {socket_ready, Socket}, StateData) when is_port(Socket) ->
    ok = inet:setopts(Socket, [{active, true}, {packet, raw}, binary]),
    {next_state, forward, StateData#state{lsock = Socket}};
init(info, Msg, Data) -> handle_info(Msg, init, Data).

forward(info, Msg, Data) -> handle_info(Msg, forward, Data).

handle_info({recv, Channel, Data}, _StateName, #state{lsock = Socket, channel = Channel} = StateData) ->
    gen_tcp:send(Socket, Data),
    {keep_state, StateData}; 
handle_info({tcp, Socket, Bin}, _StateName, #state{lsock = Socket, channel = Channel} = StateData) ->
    mimicsocks_wormhole_local:recv(Channel, Bin),
    {keep_state, StateData};
handle_info({tcp_closed, Socket}, _StateName, #state{lsock = Socket} = StateData) ->
    {stop, normal, StateData};
handle_info(Info, StateName, StateData) ->
    ?ERROR("unexpected ~p in state ~p", [Info, StateName]),
    {keep_state, StateData}.

terminate(_Reason, _StateName, #state{lsock=LSocket,
                                      channel = Channel} = _StateData) ->
    (catch gen_tcp:close(LSocket)),
    (catch mimicsocks_wormhole_local:stop(Channel)),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.