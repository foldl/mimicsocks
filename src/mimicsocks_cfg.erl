%@doc    config server
%@author foldl@outlook.com
-module(mimicsocks_cfg).

-include("mimicsocks.hrl").

-behaviour(gen_server).

-export([start_link/1, stop/0, get_value/2, get_server/1, list_servers/0, get_all/0]).
-export([register_remote/2, get_remote/1, deregister_remote/1]).

% gen-server callback functions
-export([init/1, terminate/2, 
         handle_call/3, handle_cast/2, handle_info/2, code_change/3]).

-record(state,
    {
        cfg,
        table
    }).

start_link(Config) when is_atom(Config) ->
    CfgFile = filename:join(code:priv_dir(mimicsocks), atom_to_list(Config) ++ ".cfg"),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [CfgFile], []).

stop() -> gen_server:stop(?MODULE).

% api
get_all() -> gen_server:call(?MODULE, get_all).
list_servers() -> gen_server:call(?MODULE, list_servers).
get_server(Server) -> gen_server:call(?MODULE, {get_server, Server}).
get_value(Server, Key) -> gen_server:call(?MODULE, {get_value, Server, Key}).
register_remote(ID, Pid) -> gen_server:call(?MODULE, {register_remote, ID, Pid}).
get_remote(ID) -> gen_server:call(?MODULE, {get_remote, ID}).
deregister_remote(ID) -> gen_server:call(?MODULE, {deregister_remote, ID}).

% callback functions
init([CfgFile]) ->
    {ok, Cfg} = file:consult(CfgFile),
    Tid = ets:new(table, []),
    {ok, #state{cfg = Cfg, table = Tid}}.

handle_call(get_all, _From, #state{cfg = Cfg} = State) -> 
    {reply, Cfg, State};
handle_call(list_servers, _From, #state{cfg = Cfg} = State) ->
    S = [element(1, X) || X <- Cfg],
    {reply, S, State};
handle_call({get_server, Server}, _From, #state{cfg = Cfg} = State) ->
    S = proplists:get_value(Server, Cfg),
    {reply, S, State};    
handle_call({get_value, Server, Key}, _From, #state{cfg = Cfg} = State) ->
    R = case proplists:get_value(Server, Cfg) of
        L when is_list(L) -> proplists:get_value(Key, L);
        undefined -> undefined
    end,
    {reply, R, State};
handle_call({register_remote, ID, Pid}, _From, #state{table = Tid} = State) ->
    ets:insert(Tid, {ID, Pid}),
    {reply, ok, State};
handle_call({deregister_remote, ID}, _From, #state{table = Tid} = State) ->
    ets:match_delete(Tid, {ID, '_'}),
    {reply, ok, State};
handle_call({get_remote, ID}, _From, #state{table = Tid} = State) ->
    case ets:lookup(Tid, ID) of
        [{ID, Pid}] -> {reply, {ok, Pid}, State};
        _ -> {reply, undefined, State}
    end.

handle_cast(Request, State) ->
    ?ERROR("unexpected cast msg: ~p", [Request]),
    {noreply, State}.

handle_info(Info, State) ->
    ?ERROR("unexpected info msg: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, #state{table = Tid} = _State) ->
    ets:delete(Tid),
    normal.

code_change(_OldVsn, State, _Extra) -> {ok, State}.