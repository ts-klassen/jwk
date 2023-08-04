-module(jwk_RSA_OAEP).

-export([
    generate/1
  , encrypt/2
  , decrypt/2
  , import/1
  , export/1
]).

-export_types([
    public_jwk_map/0
  , public_key/0
  , private_jwk_map/0
  , private_key/0
  , key_pair/0
]).

-type public_jwk_map() :: #{ % but key and value should be binary()
    alg     => 'RSA-OAEP'
  , e       => binary()
  , ext     => true
  , key_ops => [encrypt]
  , kty     => 'RSA'
  , n       => binary()
}.

-type public_key() :: {
    ?MODULE
  , public
  , crypto:rsa_public()
}.

-type private_jwk_map() :: #{ % but key and value should be binary()
    alg     => 'RSA-OAEP'
  , d       => binary() % D  on rsa_private()
  , dp      => binary() % E1 on rsa_private()
  , dq      => binary() % E2 on rsa_private()
  , e       => binary() % E  on rsa_private()
  , ext     => boolean()
  , key_ops => [decrypt]
  , kty     => 'RSA'
  , n       => binary() % N  on rsa_private()
  , p       => binary() % P1 on rsa_private()
  , q       => binary() % P2 on rsa_private()
  , qi      => binary() % C  on rsa_private()
}.

-type private_key() :: {
    ?MODULE
  , private
  , crypto:rsa_private()
  , Ext :: boolean()
}.

-type key_pair() :: {public_key(), private_key()}.

-spec generate(Extractable::boolean()) -> key_pair().
generate(Extractable) ->
    {Pub, Priv} = crypto:generate_key(rsa, {2048,<<1,0,1>>}),
    {
        {?MODULE, public, Pub}
      , {?MODULE, private, Priv, Extractable}
    }.

-spec encrypt(binary(), public_key() | key_pair()) -> binary().
encrypt(Text, {?MODULE, public, Key}) ->
    crypto:public_encrypt(rsa, Text, Key, [
      {rsa_padding, rsa_pkcs1_oaep_padding},{rsa_oaep_md, sha}
    ]);
encrypt(Text, {PublicKey, _}) ->
    encrypt(Text, PublicKey).

-spec decrypt(binary(), private_key() | key_pair()) -> binary().
decrypt(Data, {?MODULE, private, Key, _}) ->
    crypto:private_decrypt(rsa, Data, Key, []);
decrypt(Data, {_, PrivateKey}) ->
    decrypt(Data, PrivateKey).

-spec import(public_jwk_map())  -> public_key();
            (private_jwk_map()) -> private_key().
import(#{<<"key_ops">>:=[<<"encrypt">>]}=Jwk) ->
    import_pub_from_map(Jwk);
import(#{key_ops:=[encrypt]}=Jwk) ->
    import_pub_from_map(Jwk);
import(#{<<"key_ops">>:=[<<"decrypt">>]}=Jwk) ->
    import_priv_from_map(Jwk);
import(#{key_ops:=[decrypt]}=Jwk) ->
    import_priv_from_map(Jwk).

-spec export(public_key())  -> public_jwk_map();
            (private_key()) -> private_jwk_map().
export({_,public,_}=Key) ->
    export_pub_to_map(Key);
export({_,private,_,_}=Key) ->
    export_priv_to_map(Key).

-spec import_pub_from_map(public_jwk_map()) -> public_key().
import_pub_from_map(Jwk) ->
    <<"RSA-OAEP">> = bin_val_from_atom_key(alg, Jwk),
    <<"RSA">>          = bin_val_from_atom_key(kty, Jwk),
    E                  = bin_val_from_atom_key(  e, Jwk),
    N                  = bin_val_from_atom_key(  n, Jwk),
    {
        ?MODULE
      , public
      , [jwk_b64:decode(E), jwk_b64:decode(N)]
    }.

-spec export_pub_to_map(public_key()) -> public_jwk_map().
export_pub_to_map({?MODULE, public, [E,N]}) ->
    #{
        <<"alg">>     => <<"RSA-OAEP">>
      , <<"e">>       => jwk_b64:encode(E)
      , <<"ext">>     => true
      , <<"key_ops">> => [<<"encrypt">>]
      , <<"kty">>     => <<"RSA">>
      , <<"n">>       => jwk_b64:encode(N)
    }.

-spec import_priv_from_map(private_jwk_map()) -> private_key().
import_priv_from_map(Jwk) ->
    <<"RSA-OAEP">> = bin_val_from_atom_key(alg, Jwk),
    <<"RSA">>          = bin_val_from_atom_key(kty, Jwk),
    E                  = bin_val_from_atom_key(  e, Jwk),
    N                  = bin_val_from_atom_key(  n, Jwk),
    D                  = bin_val_from_atom_key(  d, Jwk),
    P1                 = bin_val_from_atom_key(  p, Jwk),
    P2                 = bin_val_from_atom_key(  q, Jwk),
    E1                 = bin_val_from_atom_key( dp, Jwk),
    E2                 = bin_val_from_atom_key( dq, Jwk),
    C                  = bin_val_from_atom_key( qi, Jwk),
    {
        ?MODULE
      , public
      , [
            jwk_b64:decode(E)
          , jwk_b64:decode(N)
          , jwk_b64:decode(D)
          , jwk_b64:decode(P1)
          , jwk_b64:decode(P2)
          , jwk_b64:decode(E1)
          , jwk_b64:decode(E2)
          , jwk_b64:decode(C)
        ]
      , binary_to_atom(bin_val_from_atom_key(ext, Jwk))
    }.

-spec export_priv_to_map(private_key()) -> private_jwk_map().
export_priv_to_map({?MODULE, private, [E,N,D,P1,P2,E1,E2,C], true}) ->
    #{
        <<"alg">>     => <<"RSA-OAEP">>
      , <<"d">>       => jwk_b64:encode(D)
      , <<"dp">>      => jwk_b64:encode(E1)
      , <<"dq">>      => jwk_b64:encode(E2)
      , <<"e">>       => jwk_b64:encode(E)
      , <<"ext">>     => true
      , <<"key_ops">> => [<<"decrypt">>]
      , <<"kty">>     => <<"RSA">>
      , <<"n">>       => jwk_b64:encode(N)
      , <<"p">>       => jwk_b64:encode(P1)
      , <<"q">>       => jwk_b64:encode(P2)
      , <<"qi">>      => jwk_b64:encode(C)
    };
export_priv_to_map({?MODULE, private, _, false}) ->
    error(key_is_not_extractable).

-spec bin_val_from_atom_key(atom(), map()) -> binary().
bin_val_from_atom_key(Key, Map) ->
    BinaryKey = atom_to_binary(Key),
    ListKey = atom_to_list(Key),
    Val = case Map of
        #{Key       := V} -> V;
        #{BinaryKey := V} -> V;
        #{ListKey   := V} -> V
    end,
    case Val of
        Atom   when is_atom(Atom)     -> atom_to_binary(Atom);
        List   when is_list(List)     -> list_to_binary(List);
        Binary when is_binary(Binary) -> Binary
    end.
