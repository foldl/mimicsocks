%@doc       a simple tcp server
%@author    foldl@outlook.com
-module(mimicsocks_tcp_listener).

-export([start_link/1]).

start_link([_Ip, Port, Module | _T] = Args) when is_integer(Port), is_atom(Module)->
    {ok, spawn_link(fun () -> init(Args) end)};
start_link({IpPortList, Module, FList, Args10} = _Args) when is_list(IpPortList) ->
    {ok, spawn_link(fun () -> 
        {ok, Pid} = Module:start_link(Args10),
        lists:zipwith(fun ({Ip, Port}, F) ->
            spawn_link(fun () -> init([Ip, Port, Module, {pid, F, Pid}]) end)
        end, IpPortList, FList),
        loop()
      end)}.

%% callbacks
init([Ip, Port, Module, Args]) ->
    Opts = [binary, {packet, raw}, {ip, Ip}, {backlog, 128}, {active, false}],
    case gen_tcp:listen(Port, Opts) of
        {ok, Listen_socket} ->
            case Args of
                {pid, F, Pid} when is_pid(Pid) -> 
                    link(Pid),
                    accept_loop3(Listen_socket, [Module, F, Pid]);
                {agg, Pid} when is_pid(Pid) -> accept_loop3(Listen_socket, [Module, Pid]);
                {agg, Args10} ->
                    {ok, Pid} = Module:start_link(Args10),
                    accept_loop2(Listen_socket, [Module, Pid]);
                _ -> accept_loop1(Listen_socket, [Module, Args])
            end;
        {error, Reason} ->
            {stop, Reason}
    end.

accept_loop1(LSock, [Module, Args]) ->
    case gen_tcp:accept(LSock) of
        {ok, Socket} ->
            ok = inet:setopts(Socket, [{linger, {true, 10}}]),
            {ok, Pid} = Module:start_link(Args),
            unlink(Pid),
            Module:socket_ready(Pid, Socket),
            accept_loop1(LSock, [Module, Args]);
        {error, Reason} ->
            {error, Reason}
    end.

accept_loop2(LSock, [Module, Pid]) ->
    case gen_tcp:accept(LSock) of
        {ok, Socket} ->
            ok = inet:setopts(Socket, [{linger, {true, 10}}]),
            Module:accept(Pid, Socket),
            accept_loop2(LSock, [Module, Pid]);
        {error, Reason} ->
            {error, Reason}
    end.

accept_loop3(LSock, [Module, F, Pid] = Args) ->
    case gen_tcp:accept(LSock) of
        {ok, Socket} ->
            ok = inet:setopts(Socket, [{linger, {true, 10}}]),
            Module:F(Pid, Socket),
            accept_loop3(LSock, Args);
        {error, Reason} ->
            {error, Reason}
    end.

loop() ->
    receive
        _ -> loop()
    end.