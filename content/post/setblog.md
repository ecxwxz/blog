---
title: 基于hugo的博客搭建(github+cloudflare)
description: 本文将教你0成本搭建一个博客,白嫖党狂喜
cover: https://img.cdn1.vip/i/69aa6a122deb1_1772775954.jpg
date: 2026-03-06T00:11:52+08:00
lastmod: 2026-03-06T12:30:52+08:00
---
## 基于hugo的博客搭建(github+cloudflare)
**本文教你0成本搭建一个静态博客** 白嫖党狂喜

博客分为静态和动态2种，动态博客的好处在于他可以从后台上传，有管理页面。

静态博客要考虑的就多了，比如如何上传md方便,怎么实现评论...

### 本地环境安装

#### windows

[Hugo]https://github.com/gohugoio/hugo/releases/download/v0.156.0/hugo_extended_0.156.0_windows-amd64.zip

下载后解压，记住文件路径，Win+r输入sysdm.cpl回车后依次点击，高级，环境变量，系统变量的path，

新建，然后把你的目录写进去，保存。

然后打开cmd输入hugo version

如果显示了版本号就安装完成了

```
hugo v0.156.0-9d914726dee87b0e8e3d7890d660221bde372eec+extended windows/amd64 BuildDate=2026-02-18T16:39:55Z VendorInfo=gohugoio
```

[Git]https://github.com/git-for-windows/git/releases/download/v2.53.0.windows.1/Git-2.53.0-64-bit.exe

双击运行安装即可

#### Linux

都会使用linux系统了，请根据系统选择合适的版本安装，hugo需要extend版本

### Github和Cloudflare前置准备

(可选)你可能需要一个域名，在阿里云上可以以1块钱的价格拿到一年的.top .xin域名

[阿里云域名注册]: https://wanwang.aliyun.com/newactivity/caigouji2026?utm_content=se_1023166226

![image-20260306125303064](https://img.cdn1.vip/i/69aa67f9784a2_1772775417.webp)

[将域名托管到cloudflare上]: https://juejin.cn/post/7543193023086805001

第一步：在你的**Github**主页上点击new新建一个仓库命名为blog，用于存放博客源码

![image-20260306125627553](https://img.cdn1.vip/i/69aa68162d5c5_1772775446.webp)

注册一个Cloudflare账号 

[Cloudflare官网]: dash.cloudflare.com

### 先简单搭建一个网站

#### 命令

运行以下命令，使用 [Ananke](https://github.com/theNewDynamic/gohugo-theme-ananke) 主题创建 Hugo 网站。

```
hugo new site quickstart
cd quickstart
git init
git submodule add https://github.com/theNewDynamic/gohugo-theme-ananke.git themes/ananke
echo "theme = 'ananke'" >> hugo.toml
hugo server
```

#### 命令解释 

在 `quickstart` 目录中为您的项目创建 [目录结构](https://hugo.opendocs.io/getting-started/directory-structure/)。

```text
hugo new site quickstart
```

将当前目录更改为项目的根目录。

```text
cd quickstart
```

在当前目录中初始化一个空的 Git 仓库。

```text
git init
```

将 [Ananke](https://github.com/theNewDynamic/gohugo-theme-ananke) 主题克隆到 `themes` 目录中，并将其作为 [Git 子模块](https://git-scm.com/book/en/v2/Git-Tools-Submodules) 添加到您的项目中。

```text
git submodule add https://github.com/theNewDynamic/gohugo-theme-ananke.git themes/ananke
```

向站点配置文件中追加一行，指示当前使用的主题。

```text
echo "theme = 'ananke'" >> hugo.toml
```

启动 Hugo 的开发服务器以查看网站。

```text
hugo server
```

按下 `Ctrl + C` 停止 Hugo 的开发服务器。

#### 添加内容 

向您的网站添加一个新页面。

```text
hugo new content/posts/my-first-post.md
```

Hugo 会在 `content/posts` 目录中创建该文件。使用编辑器打开该文件。

```text
---
title: "我的第一篇文章"
date: 2022-11-20T09:03:20-08:00
draft: true
---
```

注意 [front matter] 中的 `draft` 值为 `true`。默认情况下，Hugo 在构建网站时不会发布草稿内容。了解更多关于[草稿、将来和过期内容](https://hugo.opendocs.io/getting-started/usage/#draft-future-and-expired-content)的信息。

在文章正文中添加一些 [markdown]，但不要更改 `draft` 值。

```text
---
title: "我的第一篇文章"
date: 2022-11-20T09:03:20-08:00
draft: true
---
## 简介

这是 **粗体** 文本，这是 *斜体* 文本。

访问 [Hugo](https://gohugo.io) 网站！
```

保存文件，然后启动 Hugo 的开发服务器以查看网站。您可以运行以下命令之一来包含草稿内容。

```text
hugo server --buildDrafts
hugo server -D
```

在终端中显示的 URL 中查看您的网站。随着继续添加和更改内容，请保持开发服务器运行。

Hugo 的渲染引擎符合 CommonMark 的 [规范](https://spec.commonmark.org/)。CommonMark 组织提供了一个由参考实现驱动的有用的 [实时测试工具](https://spec.commonmark.org/dingus/)。

#### 配置网站 

使用编辑器打开项目根目录下的 [网站配置](https://hugo.opendocs.io/getting-started/configuration/) 文件（`hugo.toml`）。

```text
baseURL = 'https://example.org/'
languageCode = 'en-us'
title = '我的新 Hugo 网站'
theme = 'ananke'
```

进行以下更改：

1. 为您的生产网站设置 `baseURL`。该值必须以协议开头，并以斜杠结尾，如上所示。
2. 将 `languageCode` 设置为您的语言和地区。
3. 为您的生产网站设置 `title`。

启动 Hugo 的开发服务器以查看您的更改，记得包含草稿内容。

```text
hugo server -D
```

大多数主题作者提供配置指南和选项。请务必访问您的主题的存储库或文档站点了解详细信息。

Ananke 主题的作者 [The New Dynamic](https://www.thenewdynamic.com/) 提供了关于配置和使用的 [文档](https://github.com/theNewDynamic/gohugo-theme-ananke#readme)。他们还提供了一个 [演示站点](https://gohugo-ananke-theme-demo.netlify.app/)。

访问http://localhost:1313/如果显示

![image-20260306131400118](https://img.cdn1.vip/i/69aa68602c784_1772775520.webp)

说明你已经学会了Hugo的基本用法

### 完成部署

```
echo "# my-blog" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin 你的仓库名如 https://github.com/xxxxx/my-blog
git push -u origin main
```

push上去后应该会显示

![image-20260306132205876](https://img.cdn1.vip/i/69aa6878860cf_1772775544.png)

![image-20260306132217509](https://img.cdn1.vip/i/69aa6888def57_1772775560.webp)

然后来到Cloudflare的page部署页面

![image-20260306132456749](https://img.cdn1.vip/i/69aa68a4d00ea_1772775588.webp)

![image-20260306132518669](https://img.cdn1.vip/i/69aa68a3c6177_1772775587.webp)

![image-20260306132607777](https://img.cdn1.vip/i/69aa68a64ef09_1772775590.webp)

![image-20260306132753125](https://img.cdn1.vip/i/69aa68a64ef09_1772775590.webp)

**可以看到此时已经可以访问了**

![image-20260306132835030](https://img.cdn1.vip/i/69aa68b15555c_1772775601.webp)

以后你只需要

```
git add .
git commit -m xxxxxxxx
git push
```

Cloudflare会自动构建部署到网页

### 结束

你已经学会了搭建静态博客了,以后可能会出一期动态博客搭建的教程。
