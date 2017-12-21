%@doc       the supervisor
%@author    foldl@outlook.com
-module(mimicsocks_sup).
-behaviour(supervisor).

-export([start_link/0, start_link/1, start_link/2]).
-export([init/1]).

start_link() ->
    start_link(mimicsocks, fun filter_all_true/1).

start_link(skip_localhost) ->
    start_link(mimicsocks, fun filter_localhost/1);
start_link(Config) -> start_link(Config, fun filter_all_true/1).

start_link(Config, skip_localhost) -> start_link(Config, fun filter_localhost/1);
start_link(Config, IpFilter) when is_function(IpFilter) ->
    LogFile = filename:join(code:priv_dir(mimicsocks), "log"),
    mimicsocks_cfg:start_link(Config),
    error_logger:logfile({open, LogFile}),
    supervisor:start_link({local, ?MODULE}, ?MODULE, [IpFilter]).

init([IpFilter]) ->
    Servers = mimicsocks_cfg:list_servers(),
    LocalAddresses = sets:from_list(lists:filter(IpFilter, list_addrs())),

    ChildLocal = [create_local_child(LocalAddresses, X) || X <- Servers],
    ChildRemote = [create_remote_child(LocalAddresses, X) || X <- Servers],
    Children = lists:flatten(ChildLocal ++ ChildRemote),

    SupFlags = #{strategy => one_for_one, intensity => 1, period => 5},
    ChildSpecs = lists:zipwith(
        fun (Child, Id) -> maps:put(id, Id, Child) end, 
        Children, lists:seq(1, length(Children))),
    {ok, {SupFlags, ChildSpecs}}.

% helper function

%@doc list all addresses
list_addrs() ->
    {ok, L} = inet:getifaddrs(),
    lists:flatten([proplists:get_all_values(addr, X) || {_Dev, X} <- L]).

%@doc create child spec for local node
create_local_child(LocalAddresses, Server) ->
    {Ip, Port} = mimicsocks_cfg:get_value(Server, local),
    {RemoteIp, RemotePort} = mimicsocks_cfg:get_value(Server, remote),
    Key = mimicsocks_cfg:get_value(Server, key),
    OtherPorts = mimicsocks_cfg:get_value(Server, remote_extra_ports),
    LocalArgs = [RemoteIp, RemotePort, OtherPorts, Key],
    case sets:is_element(Ip, LocalAddresses) of
        true -> 
            LocalServerArgs = [Ip, Port, mimicsocks_local, LocalArgs],
            #{
                start => {mimicsocks_tcp_listener, start_link, [LocalServerArgs]},
                restart => permanent,
                shutdown => brutal_kill
            };
        _ -> []
    end.

%@doc create child spec for remote node
create_remote_child(LocalAddresses, Server) ->
    {RemoteIp, RemotePort} = mimicsocks_cfg:get_value(Server, remote),
    Key = mimicsocks_cfg:get_value(Server, key),
    {Handler, HandlerArgs} = case mimicsocks_cfg:get_value(Server, remote_handler) of
        socks5 -> {mimicsocks_remote_socks, []};
        {relay, {RelayIp, RelayPort}} ->
            {mimicsocks_remote_relay, [RelayIp, RelayPort]};
        {relay, ProxyName} when is_atom(ProxyName) ->
            {RelayIp, RelayPort} = mimicsocks_cfg:get_value(ProxyName, local),
            {mimicsocks_remote_relay, [RelayIp, RelayPort]}
    end,

    ExtraPorts = mimicsocks_cfg:get_value(Server, remote_extra_ports),
        
    case sets:is_element(RemoteIp, LocalAddresses) of
        true -> 
            RemoteArgs = [Key, Handler, HandlerArgs],
            RemoteServerArgs = [RemoteIp, RemotePort, mimicsocks_remote, RemoteArgs],
            RemoteMain = #{
                start => {mimicsocks_tcp_listener, start_link, [RemoteServerArgs]},
                restart => permanent,
                shutdown => brutal_kill
            },
            HoWorkers = [#{
                start => {mimicsocks_tcp_listener, start_link, 
                          [[RemoteIp, APort, mimicsocks_remote_ho, []]]},
                restart => permanent,
                shutdown => brutal_kill
            } || APort <- ExtraPorts],
            [RemoteMain | HoWorkers];
        _ -> []
    end.

filter_all_true(_) -> true.

filter_localhost({127,0,0,1}) -> false;
filter_localhost({0,0,0,0,0,0,0,1}) -> false;
filter_localhost(_) -> true.