%@doc       a simple tcp server
%@author    foldl@outlook.com
-module(mimicsocks_tcp_listener).

-export([start_link/1]).

start_link([_Ip, Port, Module | _T] = Args) when is_integer(Port), is_atom(Module)->
    {ok, spawn_link(fun () -> init(Args) end)}.

%% callbacks
init([Ip, Port | T]) ->
    process_flag(trap_exit, true),
    Opts = [binary, {packet, raw}, {ip, Ip},
            {keepalive, true}, {backlog, 30}, {active, false}],
    case gen_tcp:listen(Port, Opts) of
        {ok, Listen_socket} ->
            accept_loop(Listen_socket, list_to_tuple(T));
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
    end;
accept_loop(LSock, {Module}) ->
    case gen_tcp:accept(LSock) of
        {ok, Socket} ->
            ok = inet:setopts(Socket, [{linger, {true, 10}}]),
            Module:accept(Socket),
            accept_loop(LSock, {Module});
        {error, Reason} ->
            {error, Reason}
    end.
