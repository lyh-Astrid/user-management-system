# 🛡️ 用户信息管理平台 — Web 安全漏洞分析与修复实战

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=flat&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white)
![Security](https://img.shields.io/badge/Security-Audited-success?style=flat&logo=security)

**一个包含 SQL 注入 + 文件上传 + 业务逻辑漏洞完整复现与修复的 Flask 教学演示项目**

📖 [SQL注入漏洞修复报告](./SQL注入漏洞修复报告.md) | 📖 [文件上传漏洞修复报告](./文件上传漏洞修复报告.md) | 📖 [业务逻辑漏洞修复报告](./业务逻辑漏洞修复报告.md)

</div>

---

## 📋 目录

- [1. 项目概述](#1-项目概述)
- [2. 漏洞专题一：SQL 注入](#2-漏洞专题一sql-注入)
- [3. 漏洞专题二：文件上传](#3-漏洞专题二文件上传)
- [4. 漏洞专题三：业务逻辑](#4-漏洞专题三业务逻辑)
- [5. 修复前后模式切换](#5-修复前后模式切换)
- [6. 修复效果验证](#6-修复效果验证)
- [7. 安全加固总结](#7-安全加固总结)
- [8. 快速开始](#8-快速开始)
- [9. 项目结构](#9-项目结构)

---

## 1. 项目概述

基于 Python Flask 框架构建的简易用户信息管理平台，提供登录、注册、搜索、头像上传、个人中心、充值功能。**项目的核心价值在于完整呈现了 SQL 注入、文件上传和业务逻辑三类高危漏洞从产生、复现到修复的全过程**，适合作为 Web 安全课程的实践教学案例。

### 功能矩阵

| 功能 | 路由 | 方法 | 安全状态 |
|:----:|:----:|:----:|:--------:|
| 🏠 首页 | `/` | GET | ✅ 安全 |
| 🔐 登录 | `/login` | GET/POST | ✅ 安全（密码哈希 + Session加固） |
| 📝 注册 | `/register` | GET/POST | ✅ **已修复**（原存在 SQL 注入） |
| 🔍 搜索 | `/search` | GET | ✅ **已修复**（原存在 SQL 注入） |
| 👤 个人中心 | `/profile` | GET | ✅ **已修复**（原存在 IDOR 越权） |
| 💰 充值 | `/recharge` | POST | ✅ **已修复**（原存在负数充值漏洞） |
| 📷 上传头像 | `/upload` | GET/POST | ✅ **已修复**（原存在任意文件上传） |
| 🚪 退出 | `/logout` | GET | ✅ 安全 |
| 🎮 模式切换 | `/toggle-mode` | GET | 🔧 管理员专用（演示用） |

### 预设测试账号

| 用户名 | 密码 | 角色 | 说明 |
|--------|------|:----:|------|
| `admin` | `O&0onH!n@$#n!PGz` | admin | 管理员，可切换脆弱/安全模式 |
| `alice` | `1dfa2P!a8zl0UvQC` | user | 普通用户 |

---

## 2. 漏洞专题一：SQL 注入

### 2.1 漏洞概述

| 漏洞编号 | 位置 | 类型 | 风险等级 | 状态 |
|:--------:|:----:|:----|:--------:|:----:|
| VULN-01 | `/search` | f-string 拼接 SQL | 🔴 严重 | ✅ 已修复 |
| VULN-02 | `/register` | f-string 拼接 SQL | 🔴 严重 | ✅ 已修复 |

### 2.2 漏洞原理

SQL 注入的本质是**用户输入被拼接到 SQL 语句中，改变了 SQL 的语义结构**。

```python
# ❌ 修复前：字符串拼接
sql = f"SELECT * FROM users WHERE name = '{keyword}'"
# 输入: admin' OR 1=1 --
# 结果: WHERE name = 'admin' OR 1=1 --'  ← SQL 语义被篡改

# ✅ 修复后：参数化查询
sql = "SELECT * FROM users WHERE name = ?"
cursor.execute(sql, (keyword,))
# 输入: admin' OR 1=1 --
# 结果: 单引号被转义，OR 1=1 被当作普通文本
```

### 2.3 攻击复现

```bash
# 万能查询 → 返回全部用户
GET /search?keyword=xxx' OR 1=1 --

# UNION 注入 → 窃取密码字段
GET /search?keyword=' UNION SELECT id,username,password,phone FROM users --

# 注册注入 → 创建恶意用户
POST /register
username=hacker', 'hackpass', 'hack@hack.com', '000'); --
```

### 2.4 修复方案

| 措施 | 实现方式 |
|:----|:---------|
| **参数化查询** | `?` 占位符 + 参数元组，数据与 SQL 分离 |
| **密码哈希存储** | `werkzeug.security.generate_password_hash()` (scrypt) |
| **密码不传到前端** | 模板渲染前过滤 `password` 字段 |
| **Session 安全** | `HttpOnly=True`, `SameSite='Lax'` |

> 📄 详见 [SQL注入漏洞修复报告](./SQL注入漏洞修复报告.md)

---

## 3. 漏洞专题二：文件上传

### 3.1 漏洞概述

| 漏洞编号 | 类型 | 风险等级 | 状态 |
|:--------:|:-----|:--------:|:----:|
| UPLOAD-01 | 任意文件上传（无后缀名限制） | 🔴 严重 | ✅ 已修复 |
| UPLOAD-02 | 文件内容类型未验证（伪装扩展名） | 🔴 严重 | ✅ 已修复 |
| UPLOAD-03 | 路径遍历（`../` 逃逸） | 🔴 严重 | ✅ 已修复 |
| UPLOAD-04 | 文件覆盖 | 🟡 中危 | ✅ 已修复 |
| UPLOAD-05 | 空文件名与异常处理缺失 | 🟡 中危 | ✅ 已修复 |
| UPLOAD-06 | 静态路由直接提供上传文件 | 🔴 严重 | ✅ 已修复 |

### 3.2 修复前漏洞代码

```python
# ❌ 修复前：直接保存用户上传的文件，无任何检查
@app.route("/upload", methods=["GET", "POST"])
def upload():
    ...
    file = request.files.get("file")
    if file and file.filename:
        filename = file.filename                    # 原始文件名
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)                         # 直接保存
        file_url = url_for("static", filename=f"uploads/{filename}")
```

### 3.3 修复后安全代码

```python
# ✅ 修复后：4 层安全检查后才保存
@app.route("/upload", methods=["GET", "POST"])
def upload():
    ...
    file = request.files.get("file")

    # 第①层：文件是否存在
    if not file or not file.filename:
        return render_template("upload.html", error="请选择一个文件再上传！")

    filename = file.filename

    # 第②层：扩展名白名单检查
    if not allowed_file(filename):
        return render_template("upload.html",
            error="不允许上传该类型的文件！仅支持图片格式")

    # 第③层：安全文件名（防路径遍历）
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return render_template("upload.html", error="文件名不合法！")

    # 第④层：文件内容魔数检测（防伪装扩展名）
    file_head = file.read(512)
    file.seek(0)
    if imghdr.what(None, file_head) is None:
        return render_template("upload.html",
            error="文件内容不是合法的图片格式！")

    # 第⑤层：唯一文件名（防覆盖）
    unique_filename = f"{int(time.time())}_{safe_filename}"

    # 保存 + 专用路由提供访问
    file.save(os.path.join(UPLOAD_FOLDER, unique_filename))
    file_url = url_for("uploaded_file", filename=unique_filename)
```

### 3.4 攻击与防御对比

| 攻击手法 | 拦截层 | 修复前 | 修复后 |
|:---------|:------:|:------:|:------:|
| 上传 `shell.php` | 扩展名白名单 | ✅ 成功 | ❌ 拦截 |
| 上传 `malicious.html` | 扩展名白名单 | ✅ 成功 | ❌ 拦截 |
| 上传 `shell.php.jpg`（伪装） | 内容魔数检测 | ✅ 成功 | ❌ 拦截 |
| 路径遍历 `../../etc/x` | `secure_filename` | ✅ 可能成功 | ❌ 拦截 |
| 同名文件覆盖 | 时间戳前缀 | ✅ 覆盖 | ❌ 唯一保存 |

> 📄 详见 [文件上传漏洞修复报告](./文件上传漏洞修复报告.md)

---

## 4. 漏洞专题三：业务逻辑

### 4.1 漏洞概述

| 漏洞编号 | 类型 | 风险等级 | 状态 |
|:--------:|:------|:--------:|:----:|
| BIZ-01 | 充值金额未校验负值 | 🔴 严重 | ✅ 已修复 |
| BIZ-02 | 充值接口未做登录校验 | 🔴 严重 | ✅ 已修复 |
| BIZ-03 | 个人中心越权访问（IDOR） | 🔴 严重 | ✅ 已修复 |
| BIZ-04 | 余额可为负数 | 🟡 中危 | ✅ 已修复 |
| BIZ-05 | 登录页明文泄露管理员密码 | 🔴 严重 | ✅ 已修复 |

### 4.2 漏洞原理

业务逻辑漏洞与 SQL 注入等技术漏洞不同——攻击者**完全在系统授权范围内操作**，只是利用了业务规则的不完善：

```
技术漏洞（如SQL注入）:
  攻击者:  "我要执行非法操作！"
  系统:    "不行！"
  攻击者:  "那我绕过你的防护。"  ← 系统外的攻击

业务逻辑漏洞:
  攻击者:  "我要充值-99999元！"
  系统:    "好的，余额已减少99999元。"
  攻击者:  "？？这就同意了？"    ← 系统内的漏洞！
```

### 4.3 关键修复前后对比

#### 充值负数（BIZ-01）

```python
# ❌ 修复前：不做校验
amount = request.form.get("amount", type=float)
USERS_BY_ID[user_id]["balance"] += amount

# ✅ 修复后：要求金额必须为正数
amount = request.form.get("amount", type=float)
if not amount or amount <= 0:
    return redirect("/profile")
USERS_BY_ID[user_id]["balance"] += amount
```

#### 未登录充值（BIZ-02）& 越权查看资料（BIZ-03）

```python
# ❌ 修复前：从 URL/表单获取 user_id，无登录检查
user_id = request.args.get("user_id", type=int)   # /profile
user_id = request.form.get("user_id", type=int)   # /recharge

# ✅ 修复后：从 session 获取，强制登录
username = session.get("username")
if not username:
    return redirect("/login")
current_user = USERS.get(username)
user_id = current_user["id"]  # 从session获取，不信任客户端
```

#### 登录页泄露（BIZ-05）

```html
<!-- ❌ 修复前：HTML注释泄露管理员密码 -->
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: ... -->

<!-- ✅ 修复后：已删除 -->
```

### 4.4 攻击与防御对比

| 攻击手法 | 修复前 | 修复后 |
|:---------|:------:|:------:|
| 充值负数 `amount=-50000` | ✅ 余额扣减成功 | ❌ 拦截，余额不变 |
| 未登录充值 | ✅ 任意操作 | ❌ 重定向到 `/login` |
| 未登录访问个人中心 | ✅ 查看任意用户资料 | ❌ 重定向到 `/login` |
| URL 枚举 `?user_id=2` | ✅ 越权查看 alice 资料 | ❌ 参数被忽略 |
| 查看登录页 HTML 源码 | ✅ 获取管理员密码 | ❌ 无泄露 |

> 📄 详见 [业务逻辑漏洞修复报告](./业务逻辑漏洞修复报告.md)

---

## 5. 漏洞专题四：文件包含（路径遍历）

### 5.1 漏洞概述

| 漏洞编号 | 攻击方式 | 读取目标 | 风险等级 | 状态 |
|:--------:|:---------|:---------|:--------:|:----:|
| LFI-01 | `../../../etc/passwd` | 系统用户密码文件 | 🔴 严重 | ✅ 已修复 |
| LFI-02 | `../../../etc/shadow` | 密码哈希文件 | 🔴 灾难性 | ✅ 已修复 |
| LFI-03 | `../app.py` | Flask 应用源码 | 🔴 严重 | ✅ 已修复 |
| LFI-04 | URL 编码 `%2e%2e%2f` | 绕过检测读取任意文件 | 🔴 严重 | ✅ 已修复 |
| LFI-05 | `../../../../../` 多层遍历 | 深度目录穿越 | 🔴 严重 | ✅ 已修复 |
| LFI-06 | 空参数/特殊符号 | 异常路径输入 | 🟡 中危 | ✅ 已修复 |
| LFI-07 | `../data/users.db` | SQLite 数据库文件 | 🔴 灾难性 | ✅ 已修复 |

### 5.2 漏洞原理

文件包含漏洞的根源在于**将用户输入直接拼接到文件路径中，且未校验最终路径是否在预期范围内**。

```python
# ❌ 修复前：直接拼接用户输入到路径
filepath = os.path.join(PAGE_DIR, name)
# name = "../../../etc/passwd"
# filepath = "/opt/pages/../../../etc/passwd" → "/etc/passwd"
with open(filepath, "r") as f:     # ❌ 读取了系统文件！
    page_content = f.read()
```

### 5.3 攻击复现

```bash
# LFI-01: 读取系统密码文件
GET /page?name=../../../etc/passwd      → root:x:0:0:root:/root:/bin/bash

# LFI-02: 读取密码哈希
GET /page?name=../../../etc/shadow      → root:$y$j9T$...hash...

# LFI-03: 读取应用源码
GET /page?name=../app.py                → Flask 源码泄露

# LFI-04: URL 编码绕过
GET /page?name=%2e%2e%2f%2e%2e%2fetc/passwd  → 同样读取成功
```

### 5.4 五层防御修复

```python
# ✅ 修复后：五层安全防御
PAGE_DIR = "/opt/pages/"
ALLOWED_PAGES = {'help', 'about', 'faq', 'contact'}

@app.route("/page")
def page():
    name = request.args.get("name", "")

    # ❶ 白名单检查
    if name not in ALLOWED_PAGES:
        return "页面不存在"

    # ❷ 路径规范化（解析 ../）
    safe_path = os.path.realpath(os.path.join(PAGE_DIR, name))
    page_dir_real = os.path.realpath(PAGE_DIR)

    # ❸ 目录边界检查
    if not safe_path.startswith(page_dir_real + os.sep):
        return "页面不存在"

    # ❹ 文件类型限制
    if not safe_path.endswith('.html'):
        safe_path += '.html'

    # ❺ 异常捕获
    try:
        with open(safe_path, "r") as f:
            page_content = f.read()
    except:
        page_content = "页面不存在"
```

### 5.5 攻击与防御对比

| 攻击手法 | 修复前 | 修复后 | 拦截层 |
|:---------|:------:|:------:|:------|
| `../../../etc/passwd` | ✅ 读取成功 | ❌ 页面不存在 | ❶ 白名单 |
| `../../../etc/shadow` | ✅ 读取成功 | ❌ 页面不存在 | ❶ 白名单 |
| `../app.py` | ✅ 源码泄露 | ❌ 页面不存在 | ❶ 白名单 |
| URL编码 `%2e%2e%2f` | ✅ 绕过成功 | ❌ 页面不存在 | ❶ 白名单 |
| `../../../../` 多层 | ✅ 读取成功 | ❌ 页面不存在 | ❶ 白名单 |
| 空参数 | ✅ 异常行为 | ❌ 页面不存在 | ❶ 白名单 |

### 5.6 防御原理深度解析

```
白名单为什么是最有效的防御？

黑名单（无效）:
  拦截列表 = {"../", "..\\", "/etc/passwd"}
  攻击者输入: ....//....//etc/passwd     ← 绕过！
  攻击者输入: %2e%2e%2f%2e%2e%2f       ← 绕过！
  攻击者输入: ..%2f..%2f..%2f           ← 绕过！
  → 黑名单永远无法覆盖所有变形

白名单（有效）:
  允许列表 = {"help", "about", "faq", "contact"}
  攻击者输入: ../../../etc/passwd
  检查: "help" in 允许列表? → yes ✅
  检查: "../../../etc/passwd" in 允许列表? → no ❌
  → 白名单不需要理解攻击手段，只需知道什么是合法的
```

> 📄 详见 [文件包含漏洞修复报告](./文件包含漏洞修复报告.md)

---

## 6. 修复前后模式切换

为便于课堂演示，项目内置了**一键模式切换**功能，管理员可在两种模式间即时切换。

| 模式 | 搜索 SQL | 注册 SQL | 描述 |
|:----:|:---------|:---------|:-----|
| ✅ **安全模式**（默认） | `LIKE ?` 参数化查询 | `VALUES (?,?,?,?)` 参数化查询 | SQL 注入被防御 |
| ⚠️ **脆弱模式** | `LIKE '%{keyword}%'` 拼接 | f-string 拼接 | SQL 注入可被利用 |

```bash
操作方式：
  1. 以 admin 登录
  2. 首页底部点击"切换为⚠️ 脆弱模式"
  3. 导航栏红色徽章提示当前模式
  4. 控制台输出标注 [脆弱模式]/[安全模式]
```

---

## 7. 修复效果验证

### 7.1 SQL 注入防御

| 攻击手法 | 安全模式 | 脆弱模式 |
|:---------|:--------:|:--------:|
| `xxx' OR 1=1 --` | ❌ 无搜索结果 | ✅ 全部数据泄露 |
| `' UNION SELECT password...` | ❌ 无密码泄露 | ✅ 明文密码泄露 |
| `admin' AND 1=1/1=2 --`（布尔盲注） | ❌ 结果一致（盲注失效） | ✅ 可区分真假 |
| `hacker', 'hackpass', ...); --`（注册注入） | ❌ payload 被当作用户名 | ✅ 恶意用户创建成功 |

### 7.2 文件上传防御

| 攻击手法 | 修复前 | 修复后 |
|:---------|:------:|:------:|
| 上传 `shell.php`（WebShell） | ✅ 成功 | ❌ 扩展名拦截 |
| 上传 `shell.php.jpg`（伪装） | ✅ 成功 | ❌ 内容检测拦截 |
| 路径遍历 `../../etc/x` | ✅ 可能成功 | ❌ `secure_filename` 拦截 |
| 同名文件覆盖 | ✅ 后上传覆盖前者 | ❌ 时间戳区分 |
| 超大文件（>16MB） | ❌ 413（已有保护） | ❌ 413（保持） |

---

## 8. 安全加固总结

### 已实施的防护措施

```
应用层防护
├── ✅ SQL 注入防御
│   ├── 参数化查询（? 占位符）
│   └── 双路径代码（教学演示模式切换）
│
├── ✅ 文件上传防御
│   ├── 扩展名白名单（仅7种图片格式）
│   ├── 文件内容魔数检测（imghdr）
│   ├── 安全文件名（secure_filename 防路径遍历）
│   ├── 唯一文件名（时间戳防覆盖）
│   └── 专用路由提供访问（非静态目录直出）
│
├── ✅ 文件包含防御
│   ├── 页面名称白名单（仅4个预定义页面）
│   ├── 路径规范化（os.path.realpath）
│   ├── 目录边界检查（startswith 验证）
│   └── 文件扩展名限制（仅 .html）
│
├── ✅ 业务逻辑安全
│   ├── 充值金额正数校验（防负数扣减）
│   ├── 充值接口登录认证（防未登录操作）
│   ├── 个人中心权限控制（user_id 从 session 获取）
│   └── 移除登录页敏感信息泄露
│
├── ✅ 密码安全
│   ├── Scrypt 哈希存储（非明文）
│   └── 密码不传输到前端模板
│
└── ✅ Session 安全
    ├── HttpOnly Cookie（防 XSS 窃取）
    └── SameSite=Lax（防 CSRF）
```

### 安全漏洞修复全景

| 专题 | 漏洞数 | 覆盖范围 |
|:-----|:------:|:---------|
| SQL 注入 | 5 个 | f-string 拼接、密码明文存储、Session 配置 |
| 文件上传 | 6 个 | 任意文件上传、伪装扩展名、路径遍历、文件覆盖 |
| 业务逻辑 | 5 个 | 负数充值、未登录充值、IDOR 越权、余额负数、信息泄露 |
| 文件包含 | 7 个 | 路径遍历、敏感文件读取、URL编码绕过、源码泄露 |
| **合计** | **23 个** | **覆盖 Web 安全四大核心领域** |

---

## 9. 快速开始

### 环境要求

```bash
pip install flask werkzeug
```

### 运行

```bash
git clone https://github.com/lyh-Astrid/user-management-system.git
cd user-management-system
python app.py
```

打开浏览器访问 **http://localhost:5000**

### 安全测试指引

```bash
# SQL 注入测试（安全模式下应被拦截）
curl "http://localhost:5000/search?keyword=xxx'%20OR%201=1%20--"

# 文件上传测试（应被拦截）
curl -X POST http://localhost:5000/upload \
  -F "file=@shell.php" -b "session=xxx"
```

---

## 10. 项目结构

```
user-management-system/
├── app.py                              # Flask 主应用
├── README.md                           # 项目文档
├── SQL注入漏洞修复报告.md               # SQL 注入专题报告
├── 文件上传漏洞修复报告.md               # 文件上传专题报告
├── 业务逻辑漏洞修复报告.md               # 业务逻辑专题报告
├── 文件包含漏洞修复报告.md               # 文件包含专题报告
├── .gitignore
│
├── pages/                              # 动态页面目录
│   ├── help.html                       # 帮助中心
│   └── about.html                      # 关于本站
│
├── templates/
│   ├── base.html                       # 基础模板（导航栏 + 模式徽章）
│   ├── index.html                      # 首页（搜索 + 模式切换）
│   ├── login.html                      # 登录页面
│   ├── register.html                   # 注册页面
│   ├── upload.html                     # 上传页面
│   └── profile.html                    # 个人中心页面
│
├── static/
│   ├── css/style.css                   # 样式文件
│   └── uploads/                        # 上传文件访问目录
│
└── uploads/                            # 上传文件存储目录
```

---

<div align="center">

**项目状态: ✅ 安全漏洞已全部修复** | **覆盖 SQL 注入 + 文件上传 + 业务逻辑 + 文件包含 四大专题**

📄 [SQL注入漏洞修复报告](./SQL注入漏洞修复报告.md) | 📄 [文件上传漏洞修复报告](./文件上传漏洞修复报告.md) | 📄 [业务逻辑漏洞修复报告](./业务逻辑漏洞修复报告.md) | 📄 [文件包含漏洞修复报告](./文件包含漏洞修复报告.md)

</div>
