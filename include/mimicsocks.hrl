%% logging
-define(INFO(Format, L), error_logger:info_msg("~p: " ++ Format, [?MODULE | L])).
-define(WARNING(Format, L), error_logger:warning_msg("~p: " ++ Format, [?MODULE | L])).
-define(ERROR(Format, L), error_logger:error_msg("~p: " ++ Format, [?MODULE | L])).

-define(MIMICSOCKS_HELLO_SIZE, 16). % IVEC

% all TCP payload are protected by 256 AES stream cipher, including in-band
% transmission, excluding IVEC

-define(MIMICSOCKS_INBAND_PAYLOAD, 8).
-define(MIMICSOCKS_INBAND_HMAC, 8).
-define(MIMICSOCKS_INBAND_SIZE, (?MIMICSOCKS_INBAND_HMAC + ?MIMICSOCKS_INBAND_PAYLOAD)).
-define(MIMICSOCKS_INBAND_NOP, 0).
-define(MIMICSOCKS_INBAND_HO_L2R, 1).
-define(MIMICSOCKS_INBAND_HO_R2L, 2).
-define(MIMICSOCKS_INBAND_HO_COMPLETE_R2L, 3).
-define(MIMICSOCKS_INBAND_HO_COMPLETE_L2R, 4).

% mimicsocks use in-band packages for client-server communication:
% in band packge ::= hmac(sha, key, commands, 8) | command0, ... 
% where, command0, command1, ... are 0-padded to 32bytes
% 
% Command definitions:
% +--------------------------+
% |  0  |   variable length  |
% +-----+--------------------+
% | cmd |   parameters       |
% +--------------------------+

% command 1: hand-over (local -> remote) 
% params ::= target port 16-bit-int/big-endian%
%
% command 2: hand-over (remote -> local)
% command 3: hand-over complete (remote -> local)
% command 4: hand-over complete (local -> remote)
% params ::= Null

%
% a baton hand-over machanism for socket. it can be initiated by local at anytime.
%
% step 1: LOCAL:
%           connect to another port on remote (rsock2), and use ID(n) to identify itself; 
%           start tapping rsock
%
%           Generation of ID(n): n is the No. of handover, while No. 0 is the initial connection
%              ID(0) = IVec
%              ID(n) = aes_stream(ID(n-1)), n >= 1
%
% step 2: REMOTE: 
%           after rsock2 is accepted, remote starts tapping rsock, 
%           send HO-R2L on rsock & R2L traffic is switched to rsock2
%
% step 3: LOCAL: 
%           once HO-R2L is received on rsock, switch R2L traffic to rsock2, and, 
%           send HO-COMPLETE-L2R on sock & L2R traffic is switched to rsock2
%
% step 4: REMOTE: 
%           received HO-COMPLETE-L2R is received, switch L2R traffic to rsock2 and
%           close rsock, HO completed.
%

%% defintions for aggregated transmission
%doc NOP command
%    <<NOP, Reserved:16/big, LEN:8/big, dummy:LEN>>
-define(AGG_CMD_NOP, 0).
%doc New socket
%   <<NEW_SOCKET, ID:16/big>>
-define(AGG_CMD_NEW_SOCKET, 1).
%doc Close socket
%   <<CLOSE_SOCKET, ID:16/big>>
-define(AGG_CMD_CLOSE_SOCKET, 2).
%doc DATA
%   <<DATA, ID:16/big, Len:16/big, data:Len/binary>>
-define(AGG_CMD_DATA, 3).
%doc small DATA 
%   <<DATA, ID:16/big, Len:8, data:Len/binary>>
-define(AGG_CMD_SMALL_DATA, 4).

