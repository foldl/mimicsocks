# Mimicsocks: 又一个 TCP 代理

Mimicsocks 是 TCP 转发器、中继、隧道、代理，在 Shadowsocks 的启发和文献 [1] 的激励下诞生。

View [English version](README.md).

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
有两种处理模块。

* 简单的 socks5 代理服务器

    用这个东西，Mimicsocks 可以实现跟 Shadowsocks 类似的功能。

    由于使用了模块化设计，这个 sock5 代理服务器可以单独使用:

    `mimicsocks_tcp_listener:start_link([Ip, Port, mimicsocks_remote_sock5, undefined]).`

* 中继

    本中继可以把数据转发到指点的 IP 地址和端口。转发到另一个 Mimicsocks 的本端即可以搭建多级
    Mimicsocks。当然，也可用该中继将数据转发到自己的 sock5 或者 HTTP 代理服务器。

...

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
