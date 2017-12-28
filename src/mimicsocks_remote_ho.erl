%@doc       Handover management
%@author    foldll@outlook.com
-module(mimicsocks_remote_ho).

-export([start_link/1, socket_ready/2]).

-include("mimicsocks.hrl").

start_link([]) ->
    {ok, spawn_link(fun f/0)}.

socket_ready(Pid, Socket) ->
    ok = gen_tcp:controlling_process(Socket, Pid),
    Pid ! {socket_read, Socket}.

f() ->
    receive
        {socket_read, Socket} ->
            {ok, ID} = gen_tcp:recv(Socket, ?MIMICSOCKS_HELLO_SIZE, 1000),
            case mimicsocks_cfg:get_remote(ID) of
                {ok, RemotePid} -> 
                    ok = gen_tcp:controlling_process(Socket, RemotePid),
                    RemotePid ! {ho_socket, Socket};
                _ ->
                    ?ERROR("cann't find IVec remote, closing",[]),
                    gen_tcp:close(Socket)
            end
    end.