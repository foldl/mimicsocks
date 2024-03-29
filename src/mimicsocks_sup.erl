%@doc       the supervisor
%@author    foldl
-module(mimicsocks_sup).
-behaviour(supervisor).

-export([start_link/0, start_link/1, start_link/2]).
-export([init/1]).

start_link() ->
    Config = case application:get_env(mimicsocks, config) of
        {ok, X} when  is_atom(X) -> X;
        _ -> mimicsocks
    end,
    start_link(Config, both).

start_link(local) ->
    start_link(mimicsocks, local);
start_link(remote) ->
    start_link(mimicsocks, remote);
start_link(both) ->
    start_link(mimicsocks, both);
start_link(Config) -> start_link(Config, both).

start_link(Config, Type) ->
    mimicsocks_cfg:start_link(Config),
    Set = sets:from_list(
        case application:get_env(mimicsocks, log) of
            {ok, L} when  is_list(L) -> L;
            _ -> []
        end),
    case sets:is_element(file, Set) of
        true ->
            LogFile = filename:join(code:priv_dir(mimicsocks), "log"),
            ok = error_logger:logfile({open, LogFile});
        _ -> ok
    end,
    error_logger:tty(true), % sets:is_element(tty, Set)),
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Type]).

init([Type]) ->
    Servers = mimicsocks_cfg:list_servers(),
    LocalAddresses = sets:from_list(list_addrs()),

    ChildLocal = case (Type == both) or (Type == local) of
        true -> [create_local_child(LocalAddresses, X) || X <- Servers];
        _ -> []
    end,
    ChildRemote = case (Type == both) or (Type == remote) of
        true -> [create_remote_child(LocalAddresses, X) || X <- Servers];
        _ -> []
    end,
    Children = lists:flatten(ChildRemote ++ ChildLocal),

    SupFlags = #{strategy => one_for_one, intensity => 10, period => 1},
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
    case mimicsocks_cfg:get_value(Server, reverse) of
        true ->
            aggregated = mimicsocks_cfg:get_value(Server, wormhole),
            create_local_child1(LocalAddresses, Server);
        _    -> create_local_child0(LocalAddresses, Server)
    end.

create_remote_child(LocalAddresses, Server) ->
    case mimicsocks_cfg:get_value(Server, reverse) of
        true ->
            aggregated = mimicsocks_cfg:get_value(Server, wormhole),
            create_remote_child1(LocalAddresses, Server);
        _    -> create_remote_child0(LocalAddresses, Server)
    end.

create_local_child0(LocalAddresses, Server) ->
    {Ip, Port} = mimicsocks_cfg:get_value(Server, server),
    {RemoteIp, RemotePort} = mimicsocks_cfg:get_value(Server, wormhole_remote),
    Key = mimicsocks_cfg:get_value(Server, key),
    OtherPorts = mimicsocks_cfg:get_value(Server, wormhole_extra_ports),
    LocalProxy = mimicsocks_cfg:get_value(Server, local_proxy),
    LocalArgs = [RemoteIp, RemotePort, OtherPorts, Key, LocalProxy],
    case sets:is_element(Ip, LocalAddresses) of
        true ->
            case mimicsocks_cfg:get_value(Server, wormhole) of
                aggregated ->
                    LocalServerArgs = [Ip, Port, mimicsocks_local_agg, {agg, LocalArgs}],
                    #{
                        start => {mimicsocks_tcp_listener, start_link, [LocalServerArgs]},
                        restart => permanent,
                        shutdown => brutal_kill
                    };
                _ ->
                    LocalServerArgs = [Ip, Port, mimicsocks_local, LocalArgs],
                    #{
                        start => {mimicsocks_tcp_listener, start_link, [LocalServerArgs]},
                        restart => permanent,
                        shutdown => brutal_kill
                    }
            end;
        _ -> []
    end.

create_local_child1(LocalAddresses, Server) ->
    {RemoteIp, RemotePort} = mimicsocks_cfg:get_value(Server, wormhole_remote),
    Key = mimicsocks_cfg:get_value(Server, key),
    OtherPorts = mimicsocks_cfg:get_value(Server, wormhole_extra_ports),
    {Handler, HandlerArgs} = get_handler_cfg(Server),

    case (not sets:is_element(RemoteIp, LocalAddresses))
         or (RemoteIp == {127,0,0,1}) of
        true ->
            RemoteArgs = [RemoteIp, RemotePort, OtherPorts, Key, Handler, HandlerArgs],
            #{
                start => {mimicsocks_remote_agg, start_link, [RemoteArgs]},
                restart => permanent,
                shutdown => brutal_kill
            };
        _ -> []
    end.

%@doc create child spec for remote node
create_remote_child0(LocalAddresses, Server) ->
    {RemoteIp, RemotePort} = mimicsocks_cfg:get_value(Server, wormhole_remote),
    Key = mimicsocks_cfg:get_value(Server, key),
    {Handler, HandlerArgs} = get_handler_cfg(Server),
    ExtraPorts = mimicsocks_cfg:get_value(Server, wormhole_extra_ports),

    Mod = case mimicsocks_cfg:get_value(Server, wormhole) of
                aggregated -> mimicsocks_remote_agg;
                _ -> mimicsocks_remote
    end,

    case sets:is_element(RemoteIp, LocalAddresses) of
        true ->
            RemoteArgs = [Key, Handler, HandlerArgs],
            RemoteServerArgs = [RemoteIp, RemotePort, Mod, RemoteArgs],
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

create_remote_child1(LocalAddresses, Server) ->
    {Ip, Port} = mimicsocks_cfg:get_value(Server, server),
    {RemoteIp, RemotePort} = mimicsocks_cfg:get_value(Server, wormhole_remote),
    Key = mimicsocks_cfg:get_value(Server, key),
    ExtraPorts = mimicsocks_cfg:get_value(Server, wormhole_extra_ports),
    LocalArgs = [Key],

    case sets:is_element(RemoteIp, LocalAddresses) of
        true ->
            RemoteServerArgs = {[{Ip, Port}, {RemoteIp, RemotePort}],
                                 mimicsocks_local_agg, [accept, accept2], LocalArgs},
            ServerCfg = #{
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
            [ServerCfg | HoWorkers];
        _ -> []
    end.

get_handler_cfg(Server) ->
    case mimicsocks_cfg:get_value(Server, handler) of
        socks5 -> {mimicsocks_remote_socks, []};
        socks4 -> {mimicsocks_remote_socks, []};
        socks  -> {mimicsocks_remote_socks, []};
        http -> {mimicsocks_remote_http, []};
        {relay, {RelayIp, RelayPort}} ->
            {mimicsocks_remote_relay, [RelayIp, RelayPort]};
        {relay, ProxyName} when is_atom(ProxyName) ->
            {RelayIp, RelayPort} = mimicsocks_cfg:get_value(ProxyName, server),
            {mimicsocks_remote_relay, [RelayIp, RelayPort]}
    end.