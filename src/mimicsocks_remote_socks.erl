%@doc    a handler of mimicsocks_remote
%        a super simple socks5 proxy
%@author foldl@outlook.com
-module(mimicsocks_remote_socks).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2, stop/1, active/2]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-define(TIMEOUT, 1000).

-import(mimicsocks_wormhole_local, [show_sock/1, report_disconn/2]).
-export([send_to_local/2]).

% FSM States
-export([
         wait_auth/3,
         wait_req/3,
         data/3
        ]).

-record(state,
        {
            local,      % local data source (e.g. mimicsocks_remote or socket)
            rsock,      % remote socket
            buff = <<>>
        }
       ).

start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

socket_ready(Pid, Sock) when is_port(Sock) ->
    ok = gen_tcp:controlling_process(Sock, Pid),
    gen_statem:cast(Pid, {socket_ready, Sock}).

active(Pid, Option) -> Pid ! {active, Option}.

stop(Pid) -> gen_statem:stop(Pid).

%% definitions for socksv5
%% https://tools.ietf.org/html/rfc1928
-define(SOCKS5_VER, 16#05).

-define(SOCKS5_AUTH_NONE,   16#00).
-define(SOCKS5_AUTH_GSSAPI, 16#01).
-define(SOCKS5_AUTH_USER,   16#02).
-define(SOCKS5_AUTH_ERR,    16#ff).

-define(SOCKS5_REQ_CONNECT,  16#01).
-define(SOCKS5_REQ_BIND,     16#02).
-define(SOCKS5_REQ_UDP_ASSOC,16#03).

-define(SOCKS5_ATYP_V4,  16#01).
-define(SOCKS5_ATYP_DOM, 16#03).
-define(SOCKS5_ATYP_V6,  16#04).

-define(SOCKS5_REP_OK,   16#00).
-define(SOCKS5_REP_FAIL, 16#01).
-define(SOCKS5_REP_NOT_ALLOWED, 16#02).
-define(SOCKS5_REP_NET_UNREACHABLE, 16#03).
-define(SOCKS5_REP_HOST_UNREACHABLE, 16#04).
-define(SOCKS5_REP_REFUSED, 16#05).
-define(SOCKS5_REP_TTL_EXPIRED, 16#06).
-define(SOCKS5_REP_CMD_NOT_SUPPORTED, 16#07).
-define(SOCKS5_REP_ATYP_NOT_SUPPORTED, 16#08).

-define(SOCKS5_RESERVED_FIELD, 16#00).

%% definitions for socksv4
%% http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
-define(SOCKS4_VER, 16#04).
-define(SOCKS4_CMD_CONNECT,  16#01).
-define(SOCKS4_CMD_BIND,     16#02).

-define(SOCKS4_RES_GRANTED,     90).
-define(SOCKS4_RES_REJECTED,    91).
-define(SOCKS4_RES_REJECTED_CONN,    92).
-define(SOCKS4_RES_REJECTED_USERID,  93).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================
init([Local]) ->
    process_flag(trap_exit, true),
    {ok, wait_auth, #state{local = Local}}.

callback_mode() ->
    state_functions.

%%  wait_auth -> wait_req -> data
wait_auth(cast, {socket_ready, Sock}, State) ->
    ok = inet:setopts(Sock, [{active, true}]),
    {keep_state, State#state{local = Sock}};
wait_auth(cast, {local, Bin}, State) ->
    Buffer = <<(State#state.buff)/binary, Bin/binary>>,
    case decode_socks5_auth(Buffer) of 
        incomplete ->
            {next_state, wait_auth, State#state{buff = Buffer}, ?TIMEOUT};
        {?SOCKS5_VER, _, _, Rest} ->
            send_to_local(State#state.local, <<?SOCKS5_VER, ?SOCKS5_AUTH_NONE>>),
            {next_state, wait_req, State#state{buff = Rest}, ?TIMEOUT};
        {error, {not_supported_version, ?SOCKS4_VER}} ->
            do_socks4(Buffer, State);
        Error ->
            ?ERROR("socks5_auth with error: ~p~n", [Error]),
            {stop, Error, State}
    end;
wait_auth(timeout, _, State) ->
    ?ERROR("Client connection timeout: wait_req~n", []),
    {stop, normal, State};
wait_auth(info, Msg, StateData) -> handle_info(Msg, wait_auth, StateData).

do_socks4(Buffer, State) ->
    case decode_socks4_req(Buffer) of 
        incomplete ->
            {next_state, wait_auth, State#state{buff = Buffer}, ?TIMEOUT};
        {?SOCKS4_VER, DestAddr, Host, Port, Rest} = _Socks4Req ->
            case gen_tcp:connect(Host, Port, 
                                             [{active, true}, {packet, raw}, binary,
                                              {reuseaddr, true},
                                              {nodelay, true}]) of
                {ok, RSocket} ->
                    Addr = case inet:peername(RSocket) of
                        {ok, {Addr10, Port}} -> Addr10;
                        _ -> {8,8,8,8}
                    end,
                    ?INFO("Connected to remote ~p:~p for proxying", [Addr, Port]),
                    gen_tcp:send(RSocket, Rest),
                    BinAddr = list_to_binary(tuple_to_list(Addr)),
                    Socks4Rsp = <<0, ?SOCKS4_RES_GRANTED, Port:16/big, BinAddr/binary>>,
                    send_to_local(State#state.local, Socks4Rsp),
                    {next_state, data, State#state{buff= <<>>, rsock = RSocket}};
                {error, _Reason} ->
                    Socks4Rsp = <<0, ?SOCKS4_RES_REJECTED_CONN, Port:16/big, DestAddr/binary>>,
                    send_to_local(State#state.local, Socks4Rsp),
                    {stop, normal, State}
            end;
        Error ->
            ?ERROR("socks4 with error: ~p~n", [Error]),
            {stop, Error, State}
    end.

wait_req(cast, {local, Bin}, State) ->
    Buffer = <<(State#state.buff)/binary, Bin/binary>>,
    case decode_socks5_req(Buffer) of
        incomplete ->
            {next_state, wait_req, State#state{buff = Buffer}, ?TIMEOUT};
        {?SOCKS5_VER, AddrType, BinAddr, Addr, Port, Rest}->            
            Target = case AddrType of 
                ?SOCKS5_ATYP_DOM ->
                    AddrSize = size(BinAddr),
                    <<?SOCKS5_ATYP_DOM, AddrSize, BinAddr/binary, Port:16/big>>;
                _ ->
                    <<AddrType, BinAddr/binary, Port:16/big>>
            end,

            %% connect to remote server & send first message
            case gen_tcp:connect(Addr, Port, [{active, true}, {packet, raw}, binary,
                                              {reuseaddr, true},
                                              {nodelay, true}]) of
                {ok, RSocket} ->
                    ?INFO("Connected to remote ~p:~p for proxying", 
                          [Addr, Port]),
                    gen_tcp:send(RSocket, Rest),
                    Socks5Rsp = <<?SOCKS5_VER:8, ?SOCKS5_REP_OK:8, ?SOCKS5_RESERVED_FIELD:8>>,
                    send_to_local(State#state.local, [Socks5Rsp, Target]),
                    {next_state, data, 
                     State#state{buff= <<>>, rsock = RSocket}};
                {error, Reason} ->
                    ?ERROR("wait_req can't connect to remote: ~p, ~p~n", [{Addr, Port}, Reason]),
                    Socks5Rsp = <<?SOCKS5_VER:8, 1:8, ?SOCKS5_RESERVED_FIELD:8>>,
                    send_to_local(State#state.local, [Socks5Rsp, Target]),
                    {stop, normal, State}
            end;
        Error ->
            ?ERROR("wait_req with error: ~p~n", [Error]),
            {stop, Error, State}            
    end;
wait_req(timeout, _, State) ->
    ?ERROR("Client connection timeout: wait_req~n", []),
    {stop, normal, State};
wait_req(info, Msg, StateData) -> handle_info(Msg, wait_req, StateData).

data(cast, {local, Bin}, #state{rsock = Socket} = State) ->
    gen_tcp:send(Socket, Bin),
    {next_state, data, State};
data(cast, {remote, Bin}, State) ->
    send_to_local(State#state.local, Bin),
    {next_state, data, State};
data(info, Msg, StateData) -> handle_info(Msg, data, StateData).

handle_info({active, Option}, _StateName, #state{rsock = Socket} = StateData) ->
    case is_port(Socket) of
        true -> ok = inet:setopts(Socket, [{active, Option}]);
        _ -> ok
    end,
    {keep_state, StateData};
handle_info({recv, From, Bin}, StateName, StateData) when is_pid(From) ->
    ?MODULE:StateName(cast, {local, Bin}, StateData);
handle_info({tcp, Socket, Bin}, StateName, #state{local=Socket} = StateData) ->
    ?MODULE:StateName(cast, {local, Bin}, StateData);
handle_info({tcp, Socket, Bin}, StateName, #state{rsock=Socket} = StateData) ->
    ?MODULE:StateName(cast, {remote, Bin}, StateData);
handle_info({tcp_closed, Socket}, _StateName, #state{rsock = Socket} = StateData) ->
    report_disconn(Socket, "Remote"),
    {stop, normal, StateData};
handle_info({tcp_closed, Socket}, _StateName, #state{local = Socket} = StateData) ->
    report_disconn(Socket, "local"),
    {stop, normal, StateData};
handle_info(Info, StateName, State) ->
    ?ERROR("unexpected ~p", [Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, #state{rsock=RSocket}) ->
    (catch gen_tcp:close(RSocket)),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

% helper functions
send_to_local(Local, IoData) when is_pid(Local) ->
    Local ! {recv, self(), IoData};
send_to_local(LSock, IoData) when is_port(LSock) ->
    gen_tcp:send(LSock, IoData).

decode_socks5_auth(<<Ver:8/big, _/binary>>) when Ver =/= ?SOCKS5_VER ->
    {error, {not_supported_version, Ver}};
decode_socks5_auth(<<?SOCKS5_VER:8/big, NMethods:8/big, 
                     Methods:NMethods/binary, Rest/binary>>) ->
    {?SOCKS5_VER, NMethods, Methods, Rest};
decode_socks5_auth(_) ->
    incomplete.

decode_socks4_req(<<>>) -> incomplete;
decode_socks4_req(<<?SOCKS4_VER, Rem/binary>>) -> decode_socks4_req0(Rem);
decode_socks4_req(<<Ver, _/binary>>) -> {error, {not_supported_version, Ver}}.

decode_socks4_req0(<<?SOCKS4_CMD_CONNECT, DestPort:16/big, DestAddr:4/binary, Rem/binary>>) -> 
    case binary:split(Rem, <<0>>) of
        [_USERID, More] -> 
            case DestAddr of
                % socks4a
                <<0, 0, 0, X>> when X /= 0 ->
                    % socks4a
                    case binary:split(More, <<0>>) of
                        [Host, Rest] ->
                            {?SOCKS4_VER, DestAddr, binary_to_list(Host), DestPort, Rest};
                        _ -> incomplete
                    end;
                _ ->
                    {?SOCKS4_VER, DestAddr, list_to_tuple(binary_to_list(DestAddr)), DestPort, More}
            end;
        _ -> incomplete
    end;
decode_socks4_req0(<<?SOCKS4_CMD_CONNECT, _/binary>>) -> incomplete;
decode_socks4_req0(<<Cmd, _/binary>>) -> {error, {not_supported_command, Cmd}};
decode_socks4_req0(<<>>) -> incomplete.

decode_socks5_req(<<>>) -> incomplete;
decode_socks5_req(<<?SOCKS5_VER, Rem/binary>>) -> decode_socks5_req0(Rem);
decode_socks5_req(<<Ver, _/binary>>) -> {error, {not_supported_version, Ver}}.

decode_socks5_req0(<<>>) -> incomplete;
decode_socks5_req0(<<?SOCKS5_REQ_CONNECT>>) -> incomplete;
decode_socks5_req0(<<?SOCKS5_REQ_CONNECT, _>>) -> incomplete;
decode_socks5_req0(<<?SOCKS5_REQ_CONNECT, _, Rem/binary>> = _Req) -> decode_socks5_req_conn(Rem);
decode_socks5_req0(<<Cmd, _/binary>> = _Req) -> {error, {not_supported_command, Cmd}}.

decode_socks5_req_conn(<<?SOCKS5_ATYP_V4, DestAddr:4/binary, DestPort:16/big, Rem/binary>>) -> 
    {?SOCKS5_VER, ?SOCKS5_ATYP_V4, DestAddr, list_to_tuple(binary_to_list(DestAddr)), DestPort, Rem};
decode_socks5_req_conn(<<?SOCKS5_ATYP_V6, DestAddr:16/binary, DestPort:16/big, Rem/binary>>) -> 
    <<A1:16/big, A2:16/big, A3:16/big, A4:16/big, A5:16/big, A6:16/big, A7:16/big, A8:16/big>> = DestAddr,
    {?SOCKS5_VER, ?SOCKS5_ATYP_V6, DestAddr, {A1,A2,A3,A4,A5,A6,A7,A8}, DestPort, Rem};
decode_socks5_req_conn(<<?SOCKS5_ATYP_DOM, DomLen, Domain:DomLen/binary, DestPort:16/big, Rem/binary>>) ->
    {?SOCKS5_VER, ?SOCKS5_ATYP_DOM, Domain, binary_to_list(Domain), DestPort, Rem};
decode_socks5_req_conn(<<?SOCKS5_ATYP_V4, _/binary>>) -> incomplete;
decode_socks5_req_conn(<<?SOCKS5_ATYP_V6, _/binary>>) -> incomplete;
decode_socks5_req_conn(<<?SOCKS5_ATYP_DOM, _/binary>>) -> incomplete;
decode_socks5_req_conn(<<AType, _/binary>>) -> {error, {bad_atype, AType}}.