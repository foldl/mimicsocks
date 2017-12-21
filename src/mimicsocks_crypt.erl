%doc        en/decrypt module
%author     foldl@outlook.com 
-module(mimicsocks_crypt).

-export([start_link/2, stop/1, recv/2, set_cipher_state/2]).

-include_lib("mimicsocks/include/mimicsocks.hrl").

-record(state, {
    output,
    cipher
}).

start_link(encrypt, [Output, CipherState]) -> 
    spawn_link(fun() -> loop_encrypt(#state{output = Output, cipher = CipherState}) end);
start_link(decrypt, [Output, CipherState]) -> 
    spawn_link(fun() -> loop_decrypt(#state{output = Output, cipher = CipherState}) end).

stop(Pid) -> Pid ! stop.

set_cipher_state(Pid, CipherState) -> Pid ! {set_cipher_state, CipherState}.

recv(Pid, Data) -> Pid ! {recv, self(), Data}.

loop_encrypt(#state{output = Output, cipher = CipherState} = State) ->
    receive
        {recv, _From, Data} -> 
            {NewCipherState, CipherText} = crypto:stream_encrypt(CipherState, Data),
            Output ! {recv, self(), CipherText},
            loop_encrypt(State#state{cipher = NewCipherState});
        Msg ->
            handle_msg(fun loop_encrypt/1, Msg, State)
    end.

loop_decrypt(#state{output = Output, cipher = CipherState} = State) ->
    receive
        {recv, _From, Data} -> 
            {NewCipherState, CipherText} = crypto:stream_decrypt(CipherState, Data),
            Output ! {recv, self(), CipherText},
            loop_decrypt(State#state{cipher = NewCipherState});
        Msg ->
            handle_msg(fun loop_decrypt/1, Msg, State)
    end.

handle_msg(Loop, {set_cipher_state, NewCipherState}, State) -> 
    Loop(State#state{cipher = NewCipherState});
handle_msg(Loop, {flush, Ref, _From}, #state{output = Output} = State) -> 
    Output ! {flush, Ref, self()},
    Loop(State);
handle_msg(_Loop, stop, #state{output = Output} = _State) -> Output ! stop;
handle_msg(Loop, Msg, State) ->
    ?WARNING("unexpected msg: ~p", [Msg]),
    Loop(State).
