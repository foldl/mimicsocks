%@doc    a handler of mimicsocks_remote
%        a super simple http proxy
%@author foldl@outlook.com
-module(mimicsocks_remote_http).

-include("mimicsocks.hrl").

-behaviour(gen_statem).

% api
-export([start_link/1, socket_ready/2, stop/1]).

% callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-define(TIMEOUT, 1000).

-import(mimicsocks_wormhole_local, [show_sock/1, report_disconn/2]).
-import(mimicsocks_remote_socks, [send_to_local/2]).

% FSM States
-export([
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
    {ok, wait_req, #state{local = Local}}.

callback_mode() ->
    state_functions.

%%  wait_req -> data
wait_req(cast, {socket_ready, Sock}, State) ->
    ok = inet:setopts(Sock, [{active, true}]),
    {keep_state, State#state{local = Sock}};
wait_req(cast, {local, Bin}, State) ->
    Buffer = <<(State#state.buff)/binary, Bin/binary>>,
    case decode_http_req(Buffer) of
        incomplete ->
            {keep_state, State#state{buff = Buffer}, ?TIMEOUT};
        {{Host, Port, Method, Ver, RequestLine}, Headers} = _All ->
            %% connect to remote server & send first message
            case gen_tcp:connect(Host, Port, [{active, true}, {packet, raw}, binary,
                                              {reuseaddr, true}, {nodelay, true}]) of
                {ok, RSocket} ->
                    ?INFO("Connected to remote ~p:~p for proxying", [Host, Port]),
                    case Method of 
                        <<"CONNECT">> -> send_to_local(State#state.local, <<"HTTP/1.1 200 OK\r\n\r\n">>);
                        _ -> gen_tcp:send(RSocket, [RequestLine, "\r\n", Headers])
                    end,
                    {next_state, data, 
                     State#state{buff= <<>>, rsock = RSocket}};
                {error, Reason} ->
                    ?ERROR("wait_req can't connect to remote: ~p, ~p\n", [{Host, Port}, Reason]),
                    send_to_local(State#state.local, [Ver, <<" 504 Gateway Time-out\r\n">>]),
                    {stop, normal, State}
            end;
        Error ->
            ?ERROR("wait_req with error: ~p\n", [Error]),
            {stop, Error, State}            
    end;
wait_req(info, Msg, StateData) -> handle_info(Msg, wait_req, StateData).

data(cast, {local, Bin}, #state{rsock = Socket} = State) ->
    gen_tcp:send(Socket, Bin),
    {next_state, data, State};
data(cast, {remote, Bin}, State) ->
    send_to_local(State#state.local, Bin),
    {next_state, data, State};
data(info, Msg, StateData) -> handle_info(Msg, data, StateData).

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

terminate(_Reason, _StateName, #state{rsock=RSocket, local = Local}) ->
    (catch gen_tcp:close(RSocket)),
    case is_port(Local) of
        true -> (catch gen_tcp:close(Local));
        _ -> ok
    end.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

decode_http_req(Req) ->
    case binary:split(Req, <<"\r\n">>) of
        [_Data] -> incomplete;
        [Request, Headers] -> {parse_req_line(Request), Headers}
    end.

parse_req_line(Req) ->
    [Method, URL, Ver] = binary:split(Req, <<" ">>, [global]),
    {match, [Scheme, Host, Port, Path]} = re:run(
        URL, "^((?<a>http|https)://)?(?<b>[^:/]+):?(?<c>\\d*)(?<d>/?.*)",
        [{capture, all_names, binary}]),
    
    Port10 = get_port(Scheme, Port),
    Path10 = case Path of <<>> -> <<"/">>; _ -> Path end,
    RequestLine = erlang:iolist_to_binary([Method, " ", Path10, " ", Ver]),
    {binary_to_list(Host), Port10, Method, Ver, RequestLine}.

get_port(<<>>, <<>>) -> 80;
get_port(<<"http">>, <<>>) -> 80;
get_port(<<"https">>, <<>>) -> 443;
get_port(_, PortBin) -> binary_to_integer(PortBin).