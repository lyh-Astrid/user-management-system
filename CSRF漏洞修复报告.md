# CSRF 跨站请求伪造漏洞专题修复报告

<div align="center">

**项目**: 用户信息管理平台 (Flask + SQLite)  
**报告日期**: 2026-07-13  
**涉及路由**: `/change-password`, `/recharge`, `/upload`, `/register`, `/toggle-mode`

</div>

---

## 📋 目录

- [1. CSRF 漏洞概述](#1-csrf-漏洞概述)
- [2. CSRF 攻击原理](#2-csrf-攻击原理)
- [3. 漏洞详情与复现](#3-漏洞详情与复现)
  - [3.1 CSRF-01：修改密码接口无防护](#31-csrf-01修改密码接口无防护)
  - [3.2 CSRF-02：充值接口无防护](#32-csrf-02充值接口无防护)
  - [3.3 CSRF-03：文件上传接口无防护](#33-csrf-03文件上传接口无防护)
  - [3.4 CSRF-04：注册接口无防护](#34-csrf-04注册接口无防护)
  - [3.5 CSRF-05：模式切换使用GET方法](#35-csrf-05模式切换使用get方法)
- [4. 攻击场景模拟](#4-攻击场景模拟)
- [5. 修复方案详解](#5-修复方案详解)
  - [5.1 CSRF Token 生成机制](#51-csrf-token-生成机制)
  - [5.2 CSRF Token 验证机制](#52-csrf-token-验证机制)
  - [5.3 模板注入 CSRF Token](#53-模板注入-csrf-token)
  - [5.4 各表单添加 Token 隐藏字段](#54-各表单添加-token-隐藏字段)
  - [5.5 GET 方法改为 POST](#55-get-方法改为-post)
  - [5.6 修复前后代码对比](#56-修复前后代码对比)
- [6. 修复效果验证](#6-修复效果验证)
  - [6.1 攻击测试对比](#61-攻击测试对比)
  - [6.2 正常功能验证](#62-正常功能验证)
- [7. 安全加固总结](#7-安全加固总结)

---

## 1. CSRF 漏洞概述

### 1.1 什么是 CSRF

**跨站请求伪造（Cross-Site Request Forgery, CSRF）** 是一种攻击，攻击者诱使用户在已登录的 Web 应用程序中执行非本意的操作。当用户访问攻击者的恶意页面时，该页面会自动向目标站点发送伪造的请求，而浏览器会自动携带目标站点的 Cookie。

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  CSRF 攻击三要素:                                                 │
│                                                                  │
│  ① 用户已登录目标站点（浏览器持有有效的 Session Cookie）            │
│  ② 目标站点的敏感操作仅依赖 Cookie 进行身份验证                      │
│  ③ 攻击者可以预测或构造请求所需的参数                                │
│                                                                  │
│  CSRF = 用户身份被利用，而不是用户账户被盗用                         │
│         攻击者冒充用户的手，而不是冒充用户本人                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 CSRF 与 XSS 的区别

| 对比维度 | CSRF（跨站请求伪造） | XSS（跨站脚本攻击） |
|:---------|:--------------------|:--------------------|
| **攻击原理** | 利用用户身份发送伪造请求 | 在页面中注入恶意脚本 |
| **受害者** | 已登录的用户 | 访问被攻击页面的用户 |
| **目标** | 执行状态更改操作 | 窃取数据/执行脚本 |
| **防御** | CSRF Token, SameSite Cookie | 输入过滤/输出转义 |

### 1.3 本次发现漏洞总览

| 编号 | 端点 | 漏洞类型 | 风险等级 | 状态 |
|:----:|:-----|:---------|:--------:|:----:|
| **CSRF-01** | `POST /change-password` | 无 CSRF Token | 🔴 严重 | ✅ 已修复 |
| **CSRF-02** | `POST /recharge` | 无 CSRF Token | 🔴 严重 | ✅ 已修复 |
| **CSRF-03** | `POST /upload` | 无 CSRF Token | 🔴 严重 | ✅ 已修复 |
| **CSRF-04** | `POST /register` | 无 CSRF Token | 🟡 中危 | ✅ 已修复 |
| **CSRF-05** | `GET /toggle-mode` | GET 修改状态 | 🟡 中危 | ✅ 已修复 |

---

## 2. CSRF 攻击原理

### 2.1 正常请求流程

```
用户浏览器                     服务器
  │                              │
  │  POST /login                 │
  │  username=admin             │
  │  password=xxx               │
  │─────────────────────────────>│  设置 Session Cookie
  │  Set-Cookie: session=abc123 │<────────────────
  │                              │
  │  POST /change-password       │
  │  Cookie: session=abc123     │
  │  new_password=hacked        │
  │─────────────────────────────>│  验证 Cookie → 身份合法 → 执行操作
  │                              │
```

### 2.2 CSRF 攻击流程

```
用户浏览器                  攻击者网站             服务器
  │                          │                     │
  │  ✓ 用户已登录            │                     │
  │  Cookie: session=abc123  │                     │
  │                          │                     │
  │  访问攻击者网站           │                     │
  │─────────────────────────>│                     │
  │                          │                     │
  │  攻击页面包含隐藏表单:     │                     │
  │  <form action="http://   │                     │
  │   server/change-password">                     │
  │  <input name="new_       │                     │
  │   password" value="hacked">                    │
  │  </form>                                      │
  │  <script>form.submit()</script>                │
  │                          │                     │
  │  自动提交表单            │                     │
  │  (携带 Cookie!)          │                     │
  │───────────────────────────────────────────────>│
  │                          │                     │  验证 Cookie
  │                          │                     │  → 身份合法！
  │                          │                     │  → ❌ 执行了攻击操作
  │                          │                     │
```

### 2.3 为什么 Cookie 会自动发送

浏览器在发送跨站请求时，会自动携带目标站点的 Cookie，这是 HTTP Cookie 协议的标准行为。除非显式设置 `SameSite` 属性，否则 Cookie 会无条件附加到请求中。

```http
# 浏览器自动发送的 HTTP 请求头（跨域）
POST /change-password HTTP/1.1
Host: target-site.com
Cookie: session=abc123           ← 自动携带！
Origin: http://attacker-site.com ← 伪造来源
Content-Type: application/x-www-form-urlencoded

new_password=hacked
```

---

## 3. 漏洞详情与复现

### 3.1 CSRF-01：修改密码接口无防护

#### 3.1.1 漏洞信息

| 项目 | 内容 |
|:-----|:------|
| **端点** | `POST /change-password` |
| **风险等级** | 🔴 严重 |
| **CVSS 3.1** | 8.8 (High) |

#### 3.1.2 漏洞代码（修复前）

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect("/login")

    target_user = request.form.get("username", "")
    new_password = request.form.get("new_password", "")

    if target_user in USERS and new_password:
        USERS[target_user]["password"] = generate_password_hash(new_password)
    return redirect("/profile")
```

**漏洞分析**：

| 缺失的防护 | 说明 |
|:-----------|:------|
| ❌ 无 CSRF Token | 攻击者可以构造表单让受害者提交 |
| ❌ 无 Referer 校验 | 不检查请求来源 |
| ❌ 无原密码验证 | 仅凭 Cookie 即可修改密码 |
| ❌ 无身份绑定 | `username` 来自表单而非 Session |

#### 3.1.3 攻击复现

攻击者构造以下 HTML 页面，诱导已登录的受害者访问：

```html
<!-- 攻击者网站上的页面 -->
<html>
<body>
  <h1>🎉 恭喜你中奖了！</h1>

  <!-- 隐藏的 CSRF 攻击表单 -->
  <form id="csrf_form"
        action="http://victim-site.com/change-password"
        method="POST">
    <input type="hidden" name="username" value="admin">
    <input type="hidden" name="new_password" value="AttackerP@ss">
  </form>

  <!-- 页面加载后自动提交 -->
  <script>
    document.getElementById("csrf_form").submit();
  </script>
</body>
</html>
```

**攻击效果**：受害者访问该页面后，浏览器自动向目标服务器发送 POST 请求，并携带受害者的 Session Cookie。服务器收到请求后，因无 CSRF Token 验证，执行了密码修改操作。攻击者随后可使用 `AttackerP@ss` 登录管理员账户。

---

### 3.2 CSRF-02：充值接口无防护

#### 3.2.1 漏洞信息

| 项目 | 内容 |
|:-----|:------|
| **端点** | `POST /recharge` |
| **风险等级** | 🔴 严重 |

#### 3.2.2 攻击复现

```html
<form action="http://victim-site.com/recharge" method="POST">
  <input type="hidden" name="amount" value="99999">
</form>
<script>document.forms[0].submit();</script>
```

**攻击效果**：受害者在不知情的情况下给攻击者充值。

---

### 3.3 CSRF-03：文件上传接口无防护

#### 3.3.1 漏洞信息

| 项目 | 内容 |
|:-----|:------|
| **端点** | `POST /upload` |
| **风险等级** | 🔴 严重 |

无需构造表单，攻击者可以通过 `<img>` 标签配合 `enctype` 或其他方式触发 POST 上传。

---

### 3.4 CSRF-04：注册接口无防护

#### 3.4.1 漏洞信息

| 项目 | 内容 |
|:-----|:------|
| **端点** | `POST /register` |
| **风险等级** | 🟡 中危 |

---

### 3.5 CSRF-05：模式切换使用 GET 方法

#### 3.5.1 漏洞信息

| 项目 | 内容 |
|:-----|:------|
| **端点** | `GET /toggle-mode` |
| **风险等级** | 🟡 中危 |

#### 3.5.2 漏洞分析

使用 GET 方法修改服务器状态违反了 HTTP/1.1 规范（RFC 7231）：

```
RFC 7231 §4.2.1:
  GET 方法请求应只获取资源，不应有副作用。
  即：GET 请求不应修改服务器状态。

违反后果:
  <img src="http://server/toggle-mode" />
  → 浏览器加载图片时自动发送 GET 请求
  → 服务器状态被修改
  → CSRF 攻击成功！
```

---

## 4. 攻击场景模拟

### 4.1 完整的 CSRF 攻击链

```
攻击者发现漏洞:
  1. 扫描站点的 POST 端点
  2. 确认 /change-password 无 CSRF Token
  3. 确认 /recharge 无 CSRF Token

攻击者构造攻击页面:
  1. 创建恶意 HTML 页面
  2. 在页面中包含多个隐藏表单
  3. 页面加载自动提交所有表单

攻击者诱导受害者访问:
  1. 发送钓鱼邮件（"点击领取优惠券"）
  2. 在论坛中嵌入恶意链接
  3. 在广告中嵌入恶意页面

CSRF 攻击执行:
  1. 受害者的浏览器自动发送 POST 请求
  2. 浏览器自动携带受害者的 Session Cookie
  3. 服务器验证 Cookie → 身份合法 → 执行操作
  4. ✅ 攻击者密码被修改
  5. ✅ 攻击者获得管理员权限
```

### 4.2 为什么 SameSite=Lax 不足够

当前站点配置了 `SESSION_COOKIE_SAMESITE='Lax'`：

```
SameSite=Lax 的限制:
  ✅ 阻止 <form> 跨站 POST 请求携带 Cookie
  ❌ 不阻止用户通过正常链接导航后的 POST

实际绕过:
  攻击者可以在自己的域名下创建一个页面，
  通过 window.open() 打开目标站点，
  等用户交互后自动提交表单。

更严重的是:
  如果用户通过攻击者的链接打开目标站点
  （在目标站点域下执行），SameSite=Lax 完全不防御。
```

因此，**CSRF Token 是比 SameSite Cookie 更根本的防御措施**。

---

## 5. 修复方案详解

### 5.1 CSRF Token 生成机制

```python
import secrets

def generate_csrf_token():
    """生成 CSRF Token 并存入 Session"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)  # 64字符随机字符串
    return session['_csrf_token']
```

**设计要点**：

| 设计选择 | 说明 |
|:---------|:------|
| `secrets.token_hex(32)` | 使用密码学安全的随机数生成器，64字符十六进制 |
| `session['_csrf_token']` | Token 绑定到用户 Session，攻击者无法获取 |
| 只生成一次 | 同一 Session 内 Token 不变，支持多标签页操作 |

### 5.2 CSRF Token 验证机制

```python
from secrets import compare_digest

def validate_csrf_token():
    """验证 CSRF Token"""
    if not CSRF_ENABLED:
        return True
    token = session.get('_csrf_token')
    submitted = request.form.get('_csrf_token', '')
    # 使用 secrets.compare_digest 防止时序攻击
    if not token or not secrets.compare_digest(token, submitted):
        return False
    return True
```

**设计要点**：

| 设计选择 | 说明 |
|:---------|:------|
| `secrets.compare_digest()` | 常量时间比较，防止时序攻击（Timing Attack） |
| `CSRF_ENABLED` | 全局开关，方便临时关闭调试 |
| 每个 POST 路由调用 | 所有状态变更操作都受到保护 |

### 5.3 模板注入 CSRF Token

```python
@app.context_processor
def inject_csrf_token():
    """向所有模板注入 CSRF Token"""
    return dict(csrf_token=generate_csrf_token())
```

使用 Flask 的 `context_processor`，所有模板自动获得 `csrf_token` 变量，无需在每个路由中手动传递。

### 5.4 各表单添加 Token 隐藏字段

所有包含 POST 表单的模板均添加了隐藏的 CSRF Token：

```html
<!-- 每个 POST 表单第一行添加 -->
<input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
```

受影响的模板：

| 模板 | 表单 | 位置 |
|:-----|:-----|:-----|
| `profile.html` | 充值表单 | 2 个 |
| `profile.html` | 修改密码表单 | 1 个 |
| `upload.html` | 文件上传表单 | 1 个 |
| `register.html` | 注册表单 | 1 个 |
| `login.html` | 登录表单 | 1 个 |
| `index.html` | 模式切换表单 | 1 个（新改为 POST） |

### 5.5 GET 方法改为 POST

```python
# ❌ 修复前：GET 方法修改状态
@app.route("/toggle-mode")
def toggle_mode():

# ✅ 修复后：POST 方法修改状态
@app.route("/toggle-mode", methods=["POST"])
def toggle_mode():
```

并将模板中的 `<a href="/toggle-mode">` 改为：

```html
<form method="POST" action="/toggle-mode">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
    <button type="submit">切换模式</button>
</form>
```

### 5.6 修复前后代码对比

| 维度 | ❌ 修复前 | ✅ 修复后 |
|:----:|:---------|:----------|
| **Token 生成** | 无 | `secrets.token_hex(32)` |
| **Token 存储** | 无 | Session 绑定 |
| **Token 验证** | 无 | `secrets.compare_digest()` 防时序攻击 |
| **模板注入** | 无 | `context_processor` 自动注入 |
| **POST 表单** | 无 Token 字段 | 所有表单含 `_csrf_token` 隐藏字段 |
| **/toggle-mode** | GET（违反 HTTP 规范） | POST（符合规范） |
| **日志记录** | 无 | 拦截记录 `[CSRF-拦截] xxx` |

---

## 6. 修复效果验证

### 6.1 攻击测试对比

| # | 攻击手法 | 修复前 | 修复后 | 判定 |
|:-:|:---------|:------:|:------:|:----:|
| 1 | 无 Token 修改密码 | ✅ 成功修改 | ❌ 被拦截，密码不变 | ✅ **已修复** |
| 2 | 有 Token 修改密码 | ✅ 正常修改 | ✅ 正常修改 | ✅ **正常** |
| 3 | 无 Token 充值 | ✅ 成功充值 | ❌ 被拦截，余额不变 | ✅ **已修复** |
| 4 | 有 Token 充值 | ✅ 正常充值 | ✅ 正常充值 | ✅ **正常** |
| 5 | GET 修改模式 | ✅ 状态被更改 | ❌ 405 Method Not Allowed | ✅ **已修复** |
| 6 | POST + Token 切换模式 | — | ✅ 正常切换 | ✅ **正常** |

### 6.2 防御日志

```
[CSRF-拦截] 修改密码请求 Token 无效: admin
[CSRF-拦截] 充值请求 Token 无效: admin
[CSRF-拦截] 上传请求 Token 无效: admin
```

### 6.3 正常功能验证

| 功能 | Token | 结果 |
|:-----|:-----:|:----:|
| 修改密码 | ✅ 有 Token | ✅ 正常 |
| 充值 | ✅ 有 Token | ✅ 正常 |
| 上传头像 | ✅ 有 Token | ✅ 正常 |
| 注册 | ✅ 有 Token | ✅ 正常 |
| 登录 | ✅ 有 Token | ✅ 正常 |
| 切换模式 | ✅ POST + Token | ✅ 正常 |

---

## 7. 安全加固总结

### 7.1 CSRF 防御矩阵

```
CSRF 防御架构
├── 🛡️ 第一层：CSRF Token
│   ├── secrets.token_hex(32) 生成
│   ├── Session 绑定存储
│   └── secrets.compare_digest 防时序攻击
│
├── 🛡️ 第二层：SameSite Cookie
│   ├── SESSION_COOKIE_SAMESITE='Lax'
│   └── 限制跨站请求携带 Cookie
│
├── 🛡️ 第三层：HTTP 方法规范
│   ├── 状态变更操作使用 POST
│   └── GET 请求无副作用
│
└── 🛡️ 第四层：日志监控
    ├── 所有 CSRF 拦截记录日志
    └── 方便安全审计
```

### 7.2 各端点 CSRF 保护状态

| 端点 | 方法 | CSRF Token | SameSite | 方法规范 | 状态 |
|:-----|:----:|:----------:|:--------:|:--------:|:----:|
| `/change-password` | POST | ✅ | ✅ Lax | ✅ | ✅ 安全 |
| `/recharge` | POST | ✅ | ✅ Lax | ✅ | ✅ 安全 |
| `/upload` | POST | ✅ | ✅ Lax | ✅ | ✅ 安全 |
| `/register` | POST | ✅ | ✅ Lax | ✅ | ✅ 安全 |
| `/login` | POST | ✅ | ✅ Lax | ✅ | ✅ 安全 |
| `/toggle-mode` | POST | ✅ | ✅ Lax | ✅ POST | ✅ 安全 |
| `/search` | GET | — | — | ✅ 只读 | ✅ 安全 |
| `/page` | GET | — | — | ✅ 只读 | ✅ 安全 |
| `/profile` | GET | — | — | ✅ 只读 | ✅ 安全 |

### 7.3 CSRF 防御黄金法则

```
┌──────────────────────────────────────────────────────────┐
│              🥇 CSRF 防御黄金法则                         │
│                                                          │
│   1. 每个状态变更请求都必须携带 CSRF Token                │
│   2. Token 必须绑定到用户 Session                         │
│   3. Token 验证必须使用常量时间比较                        │
│   4. 状态变更操作不使用 GET 方法                           │
│   5. SameSite Cookie 作为辅助防御层                      │
│   6. 不要依赖 Referer/Origin 作为唯一防御                 │
│                                                          │
│     "Don't trust the request, trust the token."           │
│      不要信任请求本身，信任 Token。                         │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 7.4 本项目完整安全防护体系

```
项目整体安全防护（5 大专题，24+ 个漏洞）
├── ✅ SQL 注入防御（参数化查询）
├── ✅ 文件上传防御（扩展名+内容+文件名）
├── ✅ 业务逻辑安全（充值校验+权限控制）
├── ✅ 文件包含防御（白名单+路径校验+边界检查）
├── ✅ CSRF 防御（Token + SameSite + POST 方法）
├── ✅ 密码安全（Scrypt 哈希 + 前端不泄露）
└── ✅ Session 安全（HttpOnly + SameSite）
```

---

<div align="center">

**报告完毕**

*本报告覆盖了 CSRF 漏洞的发现、复现、修复、验证全流程*
*项目总共修复了五大专题 24+ 个安全漏洞*

📧 GitHub: https://github.com/lyh-Astrid/user-management-system

</div>
