---
title: 在OTP挑战期间通过2FA方法更改进行认证绕过
description: OTP 挑战期间切换 2FA 方法导致的认证绕过

date: 2026-07-25T20:12:52+08:00
lastmod: 2026-08-23T20:15:52+08:00
---
# 在OTP挑战期间通过2FA方法更改进行认证绕过

[通过在身份验证期间在电子邮件 OTP 和 TOTP 之间切换来绕过 2FA | CN-SEC 中文网](https://cn-sec.com/archives/5319543.html)

这是一个业务逻辑漏洞，作者没有提及具体是哪一个网站

## 🔍 剧情

应用默认为每个账户启用了双重认证。

用户可以配置两种认证方式之一：

- 电子邮件 OTP
- Microsoft/Google 身份验证器（TOTP）

输入有效凭证后，用户会被重定向到：

```
/customer/verify-otp/
```

## OTP2TOTP

假设攻击者已经知道受害者的电子邮件地址和密码。

登录后，应用程序请求发送电子邮件 OTP。

攻击者显然无法访问受害者的收件箱。

攻击者不输入OTP，而是直接点击：

请按回车或点击查看全尺寸图片

![img](https://miro.medium.com/v2/resize:fit:1113/1*AuxVBnikiHXPfZ_G8mOPiQ.png)

> ***无法验证？试试用 Microsoft/Google 认证器\***

应用程序会立即生成一个全新的二维码。

![img](https://miro.medium.com/v2/resize:fit:1124/1*mQuOSIjh_4Nf75BcI1kmtw.png)

攻击者通过身份验证器应用程序扫描该文件。

生成了第一个TOTP。

提交。

登录成功。

## TOTP2OTP

如果受害者已经配置了 Microsoft/Google 身份验证器，登录页面最初会请求输入 TOTP 验证码。

如果不提供认证，攻击者会将认证方式切换为电子邮件OTP。

请按回车或点击查看全尺寸图片

![img](https://miro.medium.com/v2/resize:fit:1155/1*NsL-ousAzCi9dmu_nsxJfA.png)

![img](https://miro.medium.com/v2/resize:fit:1113/1*saMFjE3jkBgeRXiTyFdPJw.png)

然后重新开始登录流程。

一旦OTP页面出现，攻击者又切换回TOTP。

请按回车或点击查看全尺寸图片

![img](https://miro.medium.com/v2/resize:fit:1113/1*AuxVBnikiHXPfZ_G8mOPiQ.png)

应用程序会生成另一个新的二维码。

![img](https://miro.medium.com/v2/resize:fit:1124/1*mQuOSIjh_4Nf75BcI1kmtw.png)

攻击者扫描了它。

生成有效的TOTP。

成功完成认证。

## 结论

这是一个利用了开发者在流程控制、权限校验、数据验证等环节的疏忽的业务逻辑漏洞，在现实中存在大量的此类漏洞，关注中间件漏洞的同时也要自查业务逻辑是否存在问题
