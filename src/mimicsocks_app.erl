%@doc       a application
%@author    foldl
-module(mimicsocks_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _Args) ->
    mimicsocks_sup:start_link().

stop(_State) ->
    ok.