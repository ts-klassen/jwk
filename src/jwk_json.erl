-module(jwk_json).

-export([
    to_map/1
  , from_map/1
]).

-type json_string() :: binary().
-type json_map() :: map().

% A function to convert json_string() <=> json_map().
% I used jsone, but you can change it if you want.

-spec to_map(json_string()) -> json_map().
to_map(Data) ->
    jsone:decode(Data).

-spec from_map(json_map()) -> json_string().
from_map(Data) ->
    jsone:encode(Data).
