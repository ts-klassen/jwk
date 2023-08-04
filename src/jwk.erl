-module(jwk).

-export([
    generate/2
  , encrypt/2
  , decrypt/2
  , import/1
  , export/1
]).

-export_types([
    jwk/0
  , name/0
  , is_extractable/0
  , public_key/0
  , private_key/0
  , key_pair/0
]).

-type jwk() :: binary().
-type name() :: 'RSA-OAEP'.
-type is_extractable() :: boolean().
-opaque public_key() :: jwk_RSA_OAEP:public_key().
-opaque private_key() :: jwk_RSA_OAEP:private_key().
-type key_pair() :: {public_key(), private_key()}.

-spec generate(name(), is_extractable()) -> key_pair().
generate('RSA-OAEP', IsExtractable) ->
    jwk_RSA_OAEP:generate(IsExtractable).

-spec encrypt(binary(), public_key() | key_pair()) -> binary().
encrypt(Data, {jwk_RSA_OAEP, _ , _}=Key) ->
    jwk_RSA_OAEP:encrypt(Data, Key);
encrypt(Data, {{jwk_RSA_OAEP, _ , _}, _}=Key) ->
    jwk_RSA_OAEP:encrypt(Data, Key).

-spec decrypt(binary(), private_key() | key_pair()) -> binary().
decrypt(Data, {jwk_RSA_OAEP, _ , _, _}=Key) ->
    jwk_RSA_OAEP:decrypt(Data, Key);
decrypt(Data, {_, {jwk_RSA_OAEP, _ , _, _}}=Key) ->
    jwk_RSA_OAEP:decrypt(Data, Key).

-spec import(jwk()) -> public_key() | private_key().
import(Jwk) ->
    JwkMap = jwk_json:to_map(Jwk),
    case JwkMap of
        #{<<"alg">>:=<<"RSA-OAEP">>} ->
            jwk_RSA_OAEP:import(JwkMap);
        #{alg:='RSA-OAEP'} ->
            jwk_RSA_OAEP:import(JwkMap)
    end.

-spec export(public_key() | private_key()) -> jwk().
export({jwk_RSA_OAEP, _ , _}=Key) ->
    JwkMap = jwk_RSA_OAEP:export(Key),
    jwk_json:from_map(JwkMap);
export({jwk_RSA_OAEP, _ , _, _}=Key) ->
    JwkMap = jwk_RSA_OAEP:export(Key),
    jwk_json:from_map(JwkMap).

