%@doc       inband transmission module
%@author    foldl@outlook.com
-module(mimicsocks_inband_send).

-export([start_link/1, stop/1, recv/2, set_key/2,
         recv_cmd/2, recv_cmd/3, get_buff/1, continue/1]).

-include("mimicsocks.hrl").

-import(mimicsocks_inband_recv, [subtract/2]).

-record(state, {
    output,
    cmd_handler,
    key,
    after_cmd,     % continue or hold_and_flush
    counter = 0,
    buff
}).

start_link([Output, Handler]) ->
    spawn_link(fun() -> loop(#state{output = Output, cmd_handler = Handler}) end).

stop(Pid) -> Pid ! stop.

recv(Pid, Data) -> Pid ! {recv, self(), Data}.

set_key(Pid, Key) -> Pid ! {set_key, Key}.
recv_cmd(Pid, Cmd) -> recv_cmd(Pid, Cmd, continue).
continue(Pid) -> Pid ! continue.

get_buff(Pid) ->
    This = self(),
    Ref = make_ref(),
    Pid ! {get_buff, This, Ref},
    receive
        {get_buff, Ref, Data} -> Data
    end.

recv_cmd(Pid, Cmd, AfterCmd) ->
    if size(Cmd) =< ?MIMICSOCKS_INBAND_PAYLOAD -> ok;
        true -> throw({size_too_large, Cmd})
    end,
    Padding = list_to_binary(lists:duplicate(?MIMICSOCKS_INBAND_PAYLOAD - size(Cmd), 0)),
    Ref = make_ref(),
    Pid ! {send_cmd, Ref, <<Cmd/binary, Padding/binary>>, AfterCmd},
    Ref.

loop_data(State, Data) when is_list(Data) ->
    lists:foldl(fun (Bin, AState) -> loop_data(AState, Bin) end, State, Data);
loop_data(#state{buff = L} = State, Data) when is_list(L) ->
    State#state{buff = [Data | L]};
loop_data(#state{output = Output} = State, Data) ->
    Output ! {recv, self(), Data},
    State.

loop(#state{output = Output} = State) ->
    receive
        continue ->
            case State#state.buff of
                L when is_list(L) ->
                    loop_data(State, lists:reverse(L));
                _ -> ok
            end,
            loop(State#state{buff = undefined});
        {recv, _From, Data} ->
            loop(loop_data(State, Data));
        {set_key, Key} ->
            loop(State#state{key = Key});
        {send_cmd, Ref, Cmd, After} ->
            Key = State#state.key,
            HMAC = mimicsocks_crypt:hmac_sha(Key, Cmd, ?MIMICSOCKS_INBAND_HMAC),
            Output ! {recv, self(), <<HMAC/binary, Cmd/binary>>},
            NewState = case After of
                continue -> State;
                hold -> State#state{buff = []}
            end,
            State#state.cmd_handler ! {cmd_sent, Ref},
            loop(NewState);
        {get_buff, Pid, Ref} ->
            L10 = case State#state.buff of
                L when is_list(L) -> lists:reverse(L);
                _ -> []
            end,
            Pid ! {get_buff, Ref, L10},
            loop(State);
        {flush, Ref, _From} ->
            State#state.output ! {flush, Ref, self()},
            loop(State);
        stop -> State#state.output ! stop;
        X ->
            ?WARNING("unexpected msg: ~p", [X]),
            loop(State)
    end.
