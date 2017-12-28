%@doc       inband transmission module
%@author    foldl@outlook.com
-module(mimicsocks_inband_recv).

-export([start_link/1, stop/1, recv/2, set_key/2, tapping/2]).
-export([subtract/2]).

-include("mimicsocks.hrl").

-record(state, {
    output,
    cmd_handler,
    key,
    tapping = false,
    buff = <<>>
}).

start_link([Output, Handler]) -> 
    spawn_link(fun() -> loop(#state{output = Output, cmd_handler = Handler}) end).

stop(Pid) -> Pid ! stop.

recv(Pid, Data) -> Pid ! {recv, self(), Data}.
set_key(Pid, Key) -> Pid ! {set_key, Key}.
tapping(Pid, Flag) -> Pid ! {tapping, Flag}.

search_cmds(Start, All, #state{output = Output, cmd_handler = Handler,
                     key = Key} = State) ->
    case All of
        <<Head:Start/binary, HMAC:?MIMICSOCKS_INBAND_HMAC/binary, 
            Cmds:?MIMICSOCKS_INBAND_PAYLOAD/binary, Rem/binary>> ->
            case crypto:hmac(sha, Key, Cmds, ?MIMICSOCKS_INBAND_HMAC) of
                HMAC ->
                    Output ! {recv, self(), Head},
                    Handler ! {inband_cmd, self(), Cmds},                   
                    search_cmds(0, Rem, State);
                _ ->
                    search_cmds(Start + 1, All, State)
            end;
        _ ->
            NextBuff = case Start > 0 of
                true -> 
                    <<Msg:Start/binary, Rem10/binary>> = All,
                    Output ! {recv, self(), Msg},
                    Rem10;
                _ -> All
            end,
            State#state{buff = NextBuff}
    end.

loop_data(Data, State) when is_list(Data) ->
    lists:foldl(fun (Bin, AState) -> loop_data(AState, Bin) end, State, Data);
loop_data(Data, #state{buff = Buff, tapping = true} = State) ->
    search_cmds(0, <<Buff/binary, Data/binary>>, State);
loop_data(Data, #state{output = Output, tapping = false} = State) ->
    Output ! {recv, self(), Data},
    State.

loop(State) ->
    receive
        {tapping, true} ->
            loop(State#state{tapping = true});
        {tapping, false} ->
            State#state.output ! {recv, self(), State#state.buff},
            loop(State#state{tapping = false, buff = <<>>});
        {recv, _From, Data} -> 
            loop(loop_data(Data, State));
        {set_key, Key} -> 
            loop(State#state{key = Key});
        {flush, Ref, _From} ->
            State#state.output ! {flush, Ref, self()},
            loop(State);
        stop -> State#state.output ! stop;
        X ->
            ?WARNING("unexpected msg: ~p", [X]),
            loop(State)
    end.

subtract(X, Y) when is_integer(X) -> X - Y;
subtract(_X, _Y) -> infinity.
