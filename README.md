# Mimicsocks: just another TCP proxy

[![Build Status](https://travis-ci.org/foldl/mimicsocks.svg?branch=master)](https://travis-ci.org/foldl/mimicsocks)

Mimicsocks is just another TCP forwarder, relay, tunnel or proxy, inspired by Shadowsocks and stimulated by [1].

查看[简体中文版](README.zh.md).

```
                                                    handlers

                                                   +--------+
                                              +---->  http  <-->
                                              |    +--------+
                                              |
+-----------+    wormhole    +------------+   |    +--------+
|   local   <- - - - - - - - >   remote   <---+----> socks  <-->
+-----------+                +------------+   |    +--------+
                                              |
                                              |    +--------+
                                              +----> relay  <-->
                                                   +--------+
```

## Features

* Chainable

    Mimicsocks can be connected in series to create a multi-hop proxy or a likely-onion router.

* Mimic

    Mimicsocks manipluates packages size and delay, and makes baton handover randomly.

* Simple

    Mimicsocks is written in Erlang/OPT, no third-party dependencies.

## Overview

Mimicsocks is a wormhole with two ends called local & remote end respectively.
Both ends are specified by an IP address and port.

Data put into the local end will be transmitted to the remote end
secretly and magically. Once data arrives at the remote end, it is served by
a data handler. Mimicsocks has three handlers:

* A simple socks4/4a/5 proxy

    With it, one can use mimicsocks just like Shadowsocks.

    Thanks to the modularity, this handler can be used as a standalone socks4/4a/5 proxy:

    `mimicsocks_tcp_listener:start_link([Ip, Port, mimicsocks_remote_socks, [undefined]]).`

* A simple http proxy

    This simple proxy supports http/https and http tunnel.

    This handler can also be used as a standalone http proxy:

    `mimicsocks_tcp_listener:start_link([Ip, Port, mimicsocks_remote_http, [undefined]]).`

* A relay

    This relay forwards data to somewhere else specified by an IP address and port.
    Data can be forwarded to another mimicsocks to create a chain of proxies. Data can
    also be forwarded to your own socks5 or http proxy.

## Internals

In each end of this wormhole (a.k.a mimicsocks), there is a list of nodes.
Each node receives data in message format `{recv, From, Data}`, and pass
the processed data to the next node by sending `{recv, From, NewData}` to it.
Generally, if there is a node A in one end,
there will be a node A<sup>-1</sup> in the other end to cancel out A's effects.

There are two types of wormhole, aggregated and distributed.
For a wormhole in distributed mode, when a new socket (call it local socket)
is established on the local end, another socket (call it remote socket) between
local & remote ends is also created.
For a wormhole in aggregated mode, there is only one socket between local & remote ends,
and all traffic are aggregated into this single socket.

Mimicsocks has following nodes.

1. AES encryption/decryption

1. inband transceiving

    To support handover, mimicsocks uses these nodes for inband communication between
    local & remote ends.

    For a wormhole in distributed mode, handover means during the lifetime of local socket, new socket are
    dynamically created to take over the job from elder remote socket. In a tiny time
    frame in traffic from local to remote and traffic from remote to local occur in
    two separate sockets, so yes, it is baton handover.

    For a wormhole in aggregated mode, handover means during the lifetime of this single socket,
    a new socket is dynamically created to take over the job from elder one, and then
    the elder one is closed.

1. mimic

    This node learns the statistical characteristics of the ongoing traffic, and
    then manipluates packages size and delay to make them follow a randomly-choosen
    distribution.

    Package size may follow one of these distributions: constant, uniform or Gaussian.
    Package delay may follow one of these distributions: constant, uniform, Gaussian or exponential.

    This node does not need a A<sup>-1</sup> in the other end.

## Get Started

Take Windows as an example.

1. Install Erlang/OTP 20.0 or newer (seriously).

    Suppose it's installed in `C:\Program files\erl9.0`

1. Download this package Erlang's lib directory: `C:\Program files\erl9.0\lib`.

1. Start werl.exe, and build mimicsocks:

    ```shell
    Eshell V9.0  (abort with ^G)
    1> cd("../lib/mimicsocks").
    C:/Program files/erl9.0/lib/mimicsocks
    ok
    2> make:all().
    ......
    up_to_date
    ```

1. Config mimicsocks. Note that both ends share the same config file.

    Open `C:\Program files\erl9.0\lib\mimicsocks\priv\mimicsocks.cfg` and edit it:

    ```erlang
    {default, [   % name of this wormhole
                {local, {{127,0,0,1}, 8888}},   % local end address
                {remote, {{127,0,0,1}, 9999}},  % remote end address
                {wormhole, aggregated},         % can be aggregated (RECOMMENDED) or distributed
                {remote_handler, socks},        % socks, http, or relay (see below)
                {remote_extra_ports, [9998]},   % extra ports on remote end for handover
                {key, <<41,186,113,221,126,106,146,106,246,112,85,183,56,79,159,
                        111,44,174,51,120, 240,217,55,13,205,149,176,82,120,6,61,131>>}
                        % possible key length: 128, 192, or 256 bits
                        % use following code to generate a new key: 
                        % io:format("~p~n",[crypto:strong_rand_bytes(256 div 8)]).
            ]
    }.
    ```

    To use the relay handler, one can define another wormhole, then use it:
    ```erlang
    {default, [   % name of this wormhole
                ...
                {remote_handler, {relay, another}},
                ...
            ]
    }.
    {another, [   % name of another wormhole
                ...
            ]
    }.
    ```

    Or just relay to another address:
    ```erlang
    {default, [   % name of this wormhole
                ...
                {remote_handler, {relay, {Ip, Port}},
                ...
            ]
    }.
    ```

1. Launch mimicsocks:

    On remote & local machine:
    ```shell
    erl -eval "application:ensure_all_started(mimicsocks)" -noshell -detached
    ```

    For aggregated ones, remote end should be started ahead of local end.
----
## License

The MIT License

Copyright 2017-2018 @foldl.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

----
[1] [The Random Forest Based Detection of Shadowsock's Traffic](http://ieeexplore.ieee.org/document/8048116/)
