-module(jwk_b64).

-export([
    encode/1
  , decode/1
]).

% base64:encode/2 and decode/2 is available from Erlang/OTP 26.
% base64_26.erl came from 
% https://github.com/erlang/otp/blob/master/lib/stdlib/src/base64.erl
% change this to base64 from base64_26 if you are using version 26 or above.
-define(BASE64, base64_26).

-spec encode(Data::binary()) -> ?BASE64:base64_binary().
encode(Data) ->
    ?BASE64:encode(Data, #{padding=>false, mode=>urlsafe}).

-spec decode(?BASE64:base64_binary()) -> Data::binary().
decode(Base64) ->
    ?BASE64:decode(Base64, #{padding=>false, mode=>urlsafe}).
