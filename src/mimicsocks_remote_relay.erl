%@doc       a relay handler for remote node
%@author    foldl@outlook.com
-module(mimicsocks_remote_relay).

-export([start_link/1, stop/1, recv/2]).

-include("mimicsocks.hrl").

-record(state,
    {
        local,
        sock
    }).

%doc connect to mimicsocks proxy or another raw tcp server
start_link([Local, Addr, Port]) ->
    {ok, spawn_link(fun () -> init([Addr, Port, Local]) end)}.

recv(Pid, Bin) ->
    Pid ! {recv, self(), Bin}.

stop(Pid) -> Pid ! stop.

init([Addr, Port, Local]) ->
    % connect to remote server & send first message
    case gen_tcp:connect(Addr, Port, [{active, true}, {packet, raw}, binary,
                                      {reuseaddr, true}]) of
        {ok, Socket} ->
            loop(#state{local = Local, sock = Socket});
        {error, Reason} ->
            ?ERROR("failed to connect to mimicsocks: ~p, ~p\n", [{Addr, Port}, Reason])
    end.

loop(#state{local = Local, sock = Socket} = State) ->
    receive
        {tcp, Socket, Bin} ->
            Local ! {recv, self(), Bin},
            loop(State);
        {tcp_closed, Socket} ->
            ok;
        {recv, Local, Bin} ->
            gen_tcp:send(Socket, Bin),
            loop(State);
        stop ->
            ok;
        X ->
            ?WARNING("unexpected msg: ~p", [X]),
            loop(State)
    end.