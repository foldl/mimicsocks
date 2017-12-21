# Mimicsocks: just another TCP proxy

Mimicsocks is just another TCP forwarder, relay, tunnel or proxy, inspired by Shadowsocks and stimulated by [1].

查看[简体中文版](README.zh.md).

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
a data handler. Mimicsocks has two handlers:

* A simple socks5 proxy

    With it, one can use mimicsocks just like Shadowsocks.

    Thanks to the modularity, this handler can be used as a standalone sock5 proxy:

    `mimicsocks_tcp_listener:start_link([Ip, Port, mimicsocks_remote_sock5, undefined]).`

* A relay

    This relay forwards data to somewhere else specified by an IP address and port.
    Data can be forwarded to another mimicsocks to create a chain of proxies. Data can
    also be forwarded to your own socks5 or http proxy.

## Internals

In end of this wormhole (a.k.a mimicsocks), there is a list of nodes. Each node receives
data in message format `{recv, From, Data}`, and pass the processed data to the next
node by sending `{recv, From, NewData}` to it. Generally, if there is a node A in one
end, there will be a node A<sup>-1</sup> in the other end to cancel out A's effects.

Mimicsocks has following nodes.

1. 256bit AES encryption/decryption

1. inband transceiving

    To support handover, mimicsocks uses these nodes for inband communication between
    local & remote ends.

    Typically, when a new socket (call it local socket) is established on the local
    end, another socket (call it remote socket) between local & remote ends is also
    created. Handover means during the lifetime of local socket, new socket are
    dynamically created to take over the job from elder remote socket. In a tiny time
    frame in traffic from local to remote and traffic from remote to local occur in
    two separate sockets, so yes, it is baton handover.

1. mimic

    This node learns the statistical characteristics of the ongoing traffic, and
    then manipluates packages size and delay to make them follow a randomly-choosen
    distribution.

    Package size may follow one of these distributions: uniform and Gaussian. Package
    delay may follow one of these distributions: uniform, Gaussian and exponential.

    This node does not need a A<sup>-1</sup> in the other end.

## Get Started

Take Windows as an example.

1. Install Erlang/OTP 20.0 or newer.

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
                {remote_handler, socks5},
                {remote_extra_ports, [9998]},   % extra ports on remote end for handover
                {key, <<41,186,113,221,126,106,146,106,246,112,85,183,56,79,159,
                        111,44,174,51,120, 240,217,55,13,205,149,176,82,120,6,61,131>>} 
                        % 256bit AES key
                        % use io:format("~p~n",[crypto:strong_rand_bytes(32)]). to generate
                        % a new key
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

    On local machine:
    ```erlang
    mimicsocks_sup:start_link().
    ```

    On remote machine:
    ```erlang
    mimicsocks_sup:start_link(skip_localhost).
    ```

----
## License

The MIT License

Copyright 2017 @foldl.

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
