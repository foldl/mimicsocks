%@doc    a handler of mimicsocks_remote
%        a super simple socks5 proxy
%@author foldl@outlook.com
-module(mimicsocks_remote_socks).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2, stop/1]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-define(TIMEOUT, 1000).

-import(mimicsocks_local, [show_sock/1, report_disconn/2]).

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

stop(Pid) -> gen_statem:stop(Pid).

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
    {ok, Bin} = gen_tcp:recv(Sock, 0),
    ok = inet:setopts(Sock, [{active, once}]),
    wait_auth(cast, {local, Bin}, State#state{local = Sock});
wait_auth(cast, {local, Bin}, State) ->
    Buffer = <<(State#state.buff)/binary, Bin/binary>>,
    case decode_socks5_auth(Buffer) of 
        incomplete ->
            {next_state, wait_auth, State#state{buff = Buffer}, ?TIMEOUT};
        {?SOCKS5_VER, _, _, Rest} ->
            send_to_local(State, <<?SOCKS5_VER, ?SOCKS5_AUTH_NONE>>),
            {next_state, wait_req, State#state{buff = Rest}, ?TIMEOUT};
        Error ->
            ?ERROR("socks5_auth with error: ~p\n", [Error]),
            {stop, Error, State}
    end;
wait_auth(cast, timeout, State) ->
    ?ERROR("Client connection timeout: wait_req\n", []),
    {stop, normal, State};
wait_auth(info, Msg, StateData) -> handle_info(Msg, wait_auth, StateData).

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
            case gen_tcp:connect(Addr, Port, [{active, once}, {packet, raw}, binary,
                                              {reuseaddr, true},
                                              {nodelay, true}]) of
                {ok, RSocket} ->
                    ?INFO("Connected to remote ~p:~p for proxying", 
                          [Addr, Port]),
                    gen_tcp:send(RSocket, Rest),
                    Socks5Rsp = <<?SOCKS5_VER:8, ?SOCKS5_REP_OK:8, ?SOCKS5_RESERVED_FIELD:8>>,
                    send_to_local(State, [Socks5Rsp, Target]),
                    {next_state, data, 
                     State#state{buff= <<>>, rsock = RSocket}};
                {error, Reason} ->
                    ?ERROR("wait_req can't connect to remote: ~p, ~p\n", [{Addr, Port}, Reason]),
                    Socks5Rsp = <<?SOCKS5_VER:8, 1:8, ?SOCKS5_RESERVED_FIELD:8>>,
                    send_to_local(State, [Socks5Rsp, Target]),
                    {stop, normal, State}
            end;
        Error ->
            ?ERROR("wait_req with error: ~p\n", [Error]),
            {stop, Error, State}            
    end;
wait_req(cast, timeout, State) ->
    ?ERROR("Client connection timeout: wait_req\n", []),
    {stop, normal, State};
wait_req(info, Msg, StateData) -> handle_info(Msg, wait_req, StateData).

data(cast, {local, Bin}, #state{rsock = Socket} = State) ->
    gen_tcp:send(Socket, Bin),
    {next_state, data, State};
data(cast, {remote, Bin}, State) ->
    send_to_local(State, Bin),
    {next_state, data, State};
data(info, Msg, StateData) -> handle_info(Msg, data, StateData).

handle_info({recv, From, Bin}, StateName, StateData) when is_pid(From) ->
    ?MODULE:StateName(cast, {local, Bin}, StateData);
handle_info({tcp, Socket, Bin}, StateName, #state{local=Socket} = StateData) ->
    ok = inet:setopts(Socket, [{active, once}]),
    ?MODULE:StateName(cast, {local, Bin}, StateData);
handle_info({tcp, Socket, Bin}, StateName, #state{rsock=Socket} = StateData) ->
    inet:setopts(Socket, [{active, once}]),
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
send_to_local(#state{local = Local} = _State, IoData) when is_pid(Local) ->
    Local ! {recv, self(), IoData};
send_to_local(#state{local = LSock} = _State, IoData) when is_port(LSock) ->
    gen_tcp:send(LSock, IoData).

decode_socks5_auth(<<Ver:8/big, _/binary>>) when Ver =/= ?SOCKS5_VER ->
    {error, {not_supported_version, Ver}};
decode_socks5_auth(<<?SOCKS5_VER:8/big, NMethods:8/big, 
                     Methods:NMethods/binary, Rest/binary>>) ->
    {?SOCKS5_VER, NMethods, Methods, Rest};
decode_socks5_auth(_) ->
    incomplete.

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