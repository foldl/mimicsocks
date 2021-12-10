%doc        en/decrypt module
%author     foldl@outlook.com
-module(mimicsocks_crypt).

-export([start_link/2, stop/1, recv/2, hmac_sha/3, init_aes_ctr_enc/2, init_aes_ctr_dec/2]).

-include("mimicsocks.hrl").

-record(state, {
    output,
    cipher
}).

start_link(encrypt, [Output, CipherState]) ->
    spawn_link(fun() -> loop_encrypt(#state{output = Output, cipher = CipherState}) end);
start_link(decrypt, [Output, CipherState]) ->
    spawn_link(fun() -> loop_decrypt(#state{output = Output, cipher = CipherState}) end).

stop(Pid) -> Pid ! stop.

recv(Pid, Data) -> Pid ! {recv, self(), Data}.

loop_encrypt(#state{output = Output, cipher = CipherState} = State) ->
    receive
        {recv, _From, Data} ->
            {NewCipherState, CipherText} = stream_encrypt(CipherState, Data),
            Output ! {recv, self(), CipherText},
            loop_encrypt(State#state{cipher = NewCipherState});
        Msg ->
            handle_msg(fun loop_encrypt/1, Msg, State)
    end.

loop_decrypt(#state{output = Output, cipher = CipherState} = State) ->
    receive
        {recv, _From, Data} ->
            {NewCipherState, CipherText} = stream_decrypt(CipherState, Data),
            Output ! {recv, self(), CipherText},
            loop_decrypt(State#state{cipher = NewCipherState});
        Msg ->
            handle_msg(fun loop_decrypt/1, Msg, State)
    end.

handle_msg(Loop, {flush, Ref, _From}, #state{output = Output} = State) ->
    Output ! {flush, Ref, self()},
    Loop(State);
handle_msg(_Loop, stop, #state{output = Output} = _State) -> Output ! stop;
handle_msg(Loop, Msg, State) ->
    ?WARNING("unexpected msg: ~p", [Msg]),
    Loop(State).

-ifndef(OTP_RELEASE).
-define(OTP_RELEASE, 20).
-endif.

-if(?OTP_RELEASE >= 24).
init_aes_ctr_enc(Key, IVec) -> crypto:crypto_init(aes_256_ctr, Key, IVec, true).
init_aes_ctr_dec(Key, IVec) -> crypto:crypto_init(aes_256_ctr, Key, IVec, false).

stream_encrypt(CipherState, Data) -> {CipherState, crypto:crypto_update(CipherState, Data)}.
stream_decrypt(CipherState, Data) -> {CipherState, crypto:crypto_update(CipherState, Data)}.

hmac_sha(Key, Data, MacLength) -> crypto:macN(hmac, sha, Key, Data, MacLength).
-else.
init_aes_ctr_enc(Key, IVec) -> crypto:stream_init(aes_ctr, Key, IVec).
init_aes_ctr_dec(Key, IVec) -> crypto:stream_init(aes_ctr, Key, IVec).

stream_encrypt(CipherState, Data) -> crypto:stream_encrypt(CipherState, Data).
stream_decrypt(CipherState, Data) -> crypto:stream_decrypt(CipherState, Data).

hmac_sha(Key, Data, MacLength) -> crypto:hmac(sha, Key, Data, MacLength).
-endif.
