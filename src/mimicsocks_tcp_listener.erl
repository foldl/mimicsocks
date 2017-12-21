%@doc       a simple tcp server
%@author    foldl@outlook.com
-module(mimicsocks_tcp_listener).

-export([start_link/1]).

start_link([Ip, Port, Module, Args]) when is_integer(Port), is_atom(Module)->
    {ok, spawn_link(fun () -> init([Ip, Port, Module, Args]) end)}.

%% callbacks
init([Ip, Port, Module, Args]) ->
    process_flag(trap_exit, true),
    Opts = [binary, {packet, raw}, {ip, Ip},
            {keepalive, true}, {backlog, 30}, {active, false}],
    case gen_tcp:listen(Port, Opts) of
        {ok, Listen_socket} ->
            accept_loop(Listen_socket, {Module, Args});
        {error, Reason} ->
            {stop, Reason}
    end.

accept_loop(LSock, {Module, Args}) ->
    case gen_tcp:accept(LSock) of
        {ok, Socket} ->
            ok = inet:setopts(Socket, [{linger, {true, 10}}]),
            {ok, Pid} = Module:start_link(Args),
            Module:socket_ready(Pid, Socket),
            accept_loop(LSock, {Module, Args});
        {error, Reason} ->
            {error, Reason}
    end.
