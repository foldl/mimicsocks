%@doc       some tests
%@author    foldl@outlook.com
-module(mimicsocks_test).

-include_lib("eunit/include/eunit.hrl").
-include("mimicsocks.hrl").

-compile([export_all]).

crypt_test() ->
    Key = crypto:strong_rand_bytes(256 div 8),
    IVec = crypto:strong_rand_bytes(?MIMICSOCKS_HELLO_SIZE),
    Cipher = crypto:stream_init(aes_ctr, Key, IVec),
    Decrypt = mimicsocks_crypt:start_link(decrypt, [self(), Cipher]),
    Encrypt = mimicsocks_crypt:start_link(encrypt, [Decrypt, Cipher]),
    io:format("~p~n", [{Encrypt, Decrypt}]),
    test_data({Encrypt, Decrypt}, {<<1,2,3,4>>, <<1,2,3,4>>}),
    test_data({Encrypt, Decrypt}, {<<5, 1,2,3,4>>, <<5, 1,2,3,4>>}).

test_data({Entry, Exit}, {Data, Expected}) ->
    Entry ! {recv, self(), Data},
    receive
        {recv, Exit, Expected} -> ok;
        X -> throw(X)
    after
        1000 -> throw(timeout)
    end.


send_and_wait(Send, Msg) ->
    receive
        Msg -> ok
    after
        10 -> 
            Buf = crypto:strong_rand_bytes(rand:uniform(20) + 5),
            mimicsocks_inband_send:recv(Send, Buf),
            send_and_wait(Send, Msg)
    end.

dump_data(Pid) ->
    receive
        {recv, Pid, <<>>} -> dump_data(Pid);
        {recv, Pid, Data} -> 
            io:format("~p~n", [Data]), 
            dump_data(Pid)
    after
        1000 -> ok
    end.

socks5_server() ->
    Server = mimicsocks_tcp_listener:start_link([{127,0,0,1}, 8888, 
                                        mimicsocks_remote_socks, [undefined]]),
    Server.

http_server() ->
    spawn_link(fun http_server0/0).

http_server0() ->
    Opts = [binary, {packet, raw}, {ip, {127,0,0,1}},
            {keepalive, true}, {backlog, 30}, {active, true}],
    case gen_tcp:listen(8001, Opts) of
        {ok, LSock} ->
            io:format("http_server on 8001\n", []),
            case gen_tcp:accept(LSock) of
                {ok, Socket} ->
                    wait_req(Socket),
                    gen_tcp:send(Socket, "HTTP/1.1 200 OK\r\n"),
                    gen_tcp:send(Socket, "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"),
                    gen_tcp:send(Socket, "Content-Type: text/html; charset=UTF-8\r\n"),
                    gen_tcp:send(Socket, "Content-Encoding: UTF-8\r\n"),
                    gen_tcp:send(Socket, "Content-Length: 400000000\r\n"),
                    gen_tcp:send(Socket, "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"),
                    gen_tcp:send(Socket, "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"),
                    gen_tcp:send(Socket, "ETag: \"3f80f-1b6-3e1cb03b\"\r\n"),
                    gen_tcp:send(Socket, "Accept-Ranges: bytes\r\n"),
                    gen_tcp:send(Socket, "Connection: close\r\n\r\n"),
                    send(Socket, 0),
                    gen_tcp:close(LSock),
                    io:format("http_server stopped\n", []);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("error: ~p", [Reason]),
            {stop, Reason}
    end.

wait_req(Socket) ->
    receive
        {tcp, Socket, Bin} -> io:format("REQ: ~p~n", [Bin])
    end.

send(Socket, N) ->
    gen_tcp:send(Socket, [integer_to_list(N), ":abcdefghijklmnopqrstuvwxyz\r\n"]),
    receive
        {tcp_closed, Socket} -> ok
    after 100 ->
        send(Socket, N + 1)
    end.