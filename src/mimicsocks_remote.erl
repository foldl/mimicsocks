%@doc remote socket forwarding server
%     
%     tcp traffic is either forwarded to a socks5 handler or relayed to another mimicsocks proxy
%@author    foldl@outlook.com
-module(mimicsocks_remote).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-import(mimicsocks_local, [show_sock/1, report_disconn/2]).

% FSM States
-export([
         init/3,
         forward/3
        ]).

-record(state,
        {
            channel,
            handler,
            handler_mod
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
    {ok, Handler} = HandlerMod:start_link([self() | HandlerArgs]),
    case mimicsocks_wormhole_remote:start_link([self(), Key]) of
        {ok, Channel} ->
            {ok, init, #state{handler_mod = HandlerMod,
                              handler = Handler,
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

handle_info({recv, Channel, Data}, _StateName, #state{handler = Handler, channel = Channel} = State) ->
    Handler ! {recv, self(), Data},
    {keep_state, State}; 
handle_info({recv, Handler, Data}, _StateName, #state{handler = Handler, channel = Channel} = State) ->
    Channel ! {recv, self(), Data},
    {keep_state, State}; 
handle_info(Info, StateName, State) ->
    ?ERROR("unexpected ~p in state ~p", [Info, StateName]),
    {keep_state, State}.

terminate(_Reason, _StateName, #state{channel = Channel,
                                      handler = Handler,
                                      handler_mod = Mod}) ->
    (catch mimicsocks_wormhole_remote:stop(Channel)),
    (catch Mod:stop(Handler)),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.
