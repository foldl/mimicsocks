# Mimicsocks: 又一个 TCP 代理

[![Build Status](https://travis-ci.org/foldl/mimicsocks.svg?branch=master)](https://travis-ci.org/foldl/mimicsocks)

Mimicsocks 是 TCP 转发器、中继、隧道、代理，在 Shadowsocks 的启发和文献 [1] 的激励下诞生。

View [English version](README.md).

```
                                                    处理模块

                                                   +--------+
                                              +---->  http  <-->
                                              |    +--------+
                                              |
+-----------+      虫 洞      +------------+   |    +--------+
|   本端    <- - - - - - - - >    远端     <---+----> socks  <-->
+-----------+                +------------+   |    +--------+
                                              |
                                              |    +--------+
                                              +---->  中继  <-->
                                                   +--------+
```

## 特性

* 可串联

    多个 Mimicsocks 可以串联在一起构成多跳代理或者类似洋葱路由的玩意儿.

* 拟态

    Mimicsocks 会调整 TCP 数据包的大小、时延，工作过程中还会随机切换 Socket。

* 简单

    Mimicsocks 纯用 Erlang/OPT 实现，不依赖其它库。

## 总体

Mimicsocks 就是一个有两个端点（本端和远端）的虫洞。端点由 IP 地址和端口号指定。

进入本端的数据会被秘密地传输到远端。数据到达远端后交由数据处理模块处理。目前，Mimicsocks
有三种处理模块。

* 简单的 socks4/4a/5 代理服务器

    用这个东西，Mimicsocks 可以实现跟 Shadowsocks 类似的功能。

    由于使用了模块化设计，这个 socks4/4a/5 代理服务器可以单独使用:

    `mimicsocks_tcp_listener:start_link([Ip, Port, mimicsocks_remote_socks, [undefined]).`


* 简单的 http 代理服务器

    支持 http/https，支持 http 隧道。

    这个http 代理服务器也可以单独使用:

    `mimicsocks_tcp_listener:start_link([Ip, Port, mimicsocks_remote_http, [undefined]]).`

* 中继

    本中继可以把数据转发到指点的 IP 地址和端口。转发到另一个 Mimicsocks 的本端即可以搭建多级
    Mimicsocks。当然，也可用该中继将数据转发到自己的 sock5 或者 HTTP 代理服务器。

## 内部实现

在虫洞的两端各有一系列处理节点。每个节点通过 `{recv, From, Data}` 消息接收来自
前级节点的数据，处理后再通过 `{recv, From, NewData}` 消息把数据传递给后级节点。
一般而言，如果在一端有一个节点 A，那么在另一端就有一个对应的节点 A<sup>-1</sup>
来抵消 A 的作用，将数据还原。

有两种虫洞，聚合式和分布式。分布式虫洞会为每一个本端出现的连接请求建立一个单独
的到远端的连接，而聚合式虫洞在两端之间维持一个 TCP 连接，所有的数据
都聚合到该连接上传输。

目前 Mimicsocks 有以下处理节点。

1. AES 加解密

1. 带内传输

    为实现切换功能，mimicsocks 通过带内传输实现本端和远端之间的控制信息传递。

1. 拟态

    主动调整虫洞内传输的数据包大小、延迟，改变其统计特性。

    本节点在对端不需要相应的 A<sup>-1</sup> 节点.

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
[1] [The Random Forest Based Detection of Shadowsock's Traffic](http://ieeexplore.ieee.org/document/8048116/)
