from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, time, imghdr, secrets, urllib.request, urllib.error, urllib.parse, socket, subprocess, platform, re, json, xml.etree.ElementTree as ET

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# SQL 注入模式开关
# ⚠️ 设置为 True   → 使用 f-string 拼接 SQL（存在 SQL 注入漏洞）
# ✅ 设置为 False  → 使用参数化查询（安全模式）
VULNERABLE_MODE = False

# Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# CSRF 保护配置
CSRF_ENABLED = True  # 全局 CSRF 开关


def generate_csrf_token():
    """生成 CSRF Token 并存入 Session"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


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


@app.context_processor
def inject_csrf_token():
    """向所有模板注入 CSRF Token"""
    return dict(csrf_token=generate_csrf_token())

# 文件上传配置
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')  # 移到项目根目录，不在 static 下
UPLOAD_FOLDER_STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER_STATIC, exist_ok=True)

# 允许上传的文件扩展名白名单
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'}

def allowed_file(filename):
    """检查文件扩展名是否在白名单中"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# SQLite 数据库初始化
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
DB_PATH = os.path.join(DB_DIR, 'users.db')

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )''')
    # 插入默认用户，使用 INSERT OR IGNORE 防止重复
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'O&0onH!n@$#n!PGz', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', '1dfa2P!a8zl0UvQC', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()
    print("[数据库] 初始化完成：", DB_PATH)

# 用户数据库 - 密码以哈希形式存储
_raw_users = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password": "O&0onH!n@$#n!PGz",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "id": 2,
        "username": "alice",
        "password": "1dfa2P!a8zl0UvQC",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# 启动时自动哈希所有密码，同时构建 ID 索引
USERS = {}
USERS_BY_ID = {}
for username, info in _raw_users.items():
    user_data = dict(info)
    user_data["password"] = generate_password_hash(user_data["password"])
    USERS[username] = user_data
    USERS_BY_ID[user_data["id"]] = user_data


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        # 取出用户信息时排除密码字段，不传到前端
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", user=user_info, vulnerable_mode=VULNERABLE_MODE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 使用哈希比对密码，防止时序攻击和数据库泄露风险
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            # 登录成功后取出用户信息，排除密码字段
            user_info = {k: v for k, v in USERS[username].items() if k != "password"}
            return render_template("index.html", user=user_info, vulnerable_mode=VULNERABLE_MODE)
        else:
            return render_template("login.html", error="用户名或密码错误！")

    # 从 URL 参数中获取 success 消息（注册成功跳转）
    success = request.args.get("success", "")
    return render_template("login.html", success=success)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/toggle-mode", methods=["POST"])
def toggle_mode():
    """切换 SQL 注入模式（仅管理员可用）"""
    username = session.get("username")
    if username not in USERS or USERS[username].get("role") != "admin":
        return redirect("/")

    # CSRF Token 验证
    if not validate_csrf_token():
        print(f"[CSRF-拦截] 模式切换请求 Token 无效")
        return redirect("/")

    global VULNERABLE_MODE
    VULNERABLE_MODE = not VULNERABLE_MODE
    mode_text = "⚠️ 脆弱模式（f-string拼接）" if VULNERABLE_MODE else "✅ 安全模式（参数化查询）"
    print(f"\n{'='*50}")
    print(f"[模式切换] 已切换为: {mode_text}")
    print(f"{'='*50}\n")
    return redirect("/")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """用户头像上传（需要登录，已修复安全漏洞）"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        # CSRF Token 验证
        if not validate_csrf_token():
            print(f"[CSRF-拦截] 上传请求 Token 无效: {username}")
            return render_template("upload.html", error="安全验证失败，请重试！", username=username)

        file = request.files.get("file")

        # 检查是否选择了文件
        if not file or not file.filename:
            return render_template("upload.html", error="请选择一个文件再上传！", username=username)

        filename = file.filename

        # 检查文件扩展名（防御：恶意文件上传）
        if not allowed_file(filename):
            print(f"[上传-拦截] 用户 {username} 尝试上传不允许的文件类型: {filename}")
            return render_template("upload.html", error="不允许上传该类型的文件！仅支持图片格式（jpg, jpeg, png, gif, webp, bmp, svg）", username=username)

        # 使用 secure_filename 清理文件名（防御：路径遍历、特殊字符）
        safe_filename = secure_filename(filename)
        if not safe_filename:
            return render_template("upload.html", error="文件名不合法，请重命名后上传！", username=username)

        # 添加时间戳前缀防止文件覆盖（防御：文件名冲突覆盖）
        timestamp = str(int(time.time()))
        unique_filename = f"{timestamp}_{safe_filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        filepath_static = os.path.join(UPLOAD_FOLDER_STATIC, unique_filename)

        # 检查文件内容类型（防御：伪装扩展名攻击）
        file.seek(0)
        file_head = file.read(512)
        file.seek(0)
        image_type = imghdr.what(None, file_head)
        if image_type is None:
            print(f"[上传-拦截] 用户 {username} 上传的文件内容不是合法图片: {filename}")
            return render_template("upload.html", error="文件内容不是合法的图片格式！", username=username)

        # 保存文件
        file.save(filepath)
        # 复制到 static/uploads/ 以供访问
        import shutil
        shutil.copy2(filepath, filepath_static)

        # 通过专用路由生成访问 URL
        file_url = url_for("uploaded_file", filename=unique_filename)
        print(f"[上传] 用户 {username} 上传文件: {filename} → {unique_filename} (已安全检查)")
        return render_template("upload.html", file_url=file_url, filename=unique_filename, username=username)

    return render_template("upload.html", username=username)


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    """安全地提供上传的文件（防御：目录遍历、MIME类型嗅探）"""
    safe_filename = secure_filename(filename)
    if not safe_filename:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER_STATIC, safe_filename)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # CSRF Token 验证
        if not validate_csrf_token():
            print(f"[CSRF-拦截] 注册请求 Token 无效")
            return render_template("register.html", error="安全验证失败，请重试！", vulnerable_mode=VULNERABLE_MODE)

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            if VULNERABLE_MODE:
                # ⚠️ 脆弱模式：使用 f-string 拼接 SQL（存在 SQL 注入漏洞）
                sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
                print("[注册 SQL - 脆弱模式]", sql)
                c.execute(sql)
            else:
                # ✅ 安全模式：使用参数化查询（? 占位符）防止 SQL 注入
                sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
                print("[注册 SQL - 安全模式]", sql, "参数:", [username, password, email, phone])
                c.execute(sql, (username, password, email, phone))
            conn.commit()
            print("[注册] 用户创建成功:", username)
            return render_template("login.html", success="注册成功，请登录")
        except Exception as e:
            print("[注册] 失败:", e)
            return render_template("register.html", error=f"注册失败：{e}")
        finally:
            conn.close()

    return render_template("register.html", vulnerable_mode=VULNERABLE_MODE)


@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        if VULNERABLE_MODE:
            # ⚠️ 脆弱模式：使用 f-string 拼接 SQL（存在 SQL 注入漏洞）
            sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
            print("[搜索 SQL - 脆弱模式]", sql)
            c.execute(sql)
        else:
            # ✅ 安全模式：使用参数化查询（? 占位符）防止 SQL 注入
            sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
            like_pattern = f"%{keyword}%"
            print("[搜索 SQL - 安全模式]", sql, "参数: ['%s', '%s']" % (keyword, keyword))
            c.execute(sql, (like_pattern, like_pattern))
        rows = c.fetchall()
        print(f"[搜索] 结果数量: {len(rows)}")
    except Exception as e:
        print("[搜索] 查询失败:", e)
        rows = []
    finally:
        conn.close()

    # 获取当前登录用户信息（保持与首页一致）
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}

    return render_template("index.html", user=user_info, search_results=rows, search_keyword=keyword, vulnerable_mode=VULNERABLE_MODE)


PAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pages')

# 允许的页面名称白名单（防御：路径遍历/LFI）
ALLOWED_PAGES = {'help', 'about', 'faq', 'contact'}


@app.route("/page", methods=["GET"])
def page():
    """动态页面加载（已修复路径遍历漏洞）"""
    name = request.args.get("name", "")

    # 防御①：检查页面名称是否在白名单中
    if name not in ALLOWED_PAGES:
        print(f"[页面加载-拦截] 非白名单页面请求: {name}")
        page_content = "<h1>页面不存在</h1><p>抱歉，您访问的页面不存在。</p>"
        return render_template("index.html", page_content=page_content, vulnerable_mode=VULNERABLE_MODE)

    # 防御②：使用 os.path.realpath 规范化路径，防止目录穿越
    safe_path = os.path.realpath(os.path.join(PAGE_DIR, name))
    page_dir_real = os.path.realpath(PAGE_DIR)

    # 防御③：验证最终路径在 pages 目录内
    if not safe_path.startswith(page_dir_real + os.sep):
        print(f"[页面加载-拦截] 路径逃逸尝试: {name} → {safe_path}")
        page_content = "<h1>页面不存在</h1><p>抱歉，您访问的页面不存在。</p>"
        return render_template("index.html", page_content=page_content, vulnerable_mode=VULNERABLE_MODE)

    # 防御④：只允许加载 .html 文件
    if not safe_path.endswith('.html'):
        safe_path += '.html'

    print(f"[页面加载] 安全路径: {safe_path}")

    page_content = None
    if os.path.isfile(safe_path):
        try:
            with open(safe_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        except Exception as e:
            print(f"[页面加载] 读取失败: {e}")
            page_content = "<h1>页面不存在</h1><p>抱歉，读取页面时出错。</p>"
    else:
        page_content = "<h1>页面不存在</h1><p>抱歉，您访问的页面不存在。</p>"

    # 获取当前登录用户信息
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}

    return render_template("index.html", user=user_info, page_content=page_content, vulnerable_mode=VULNERABLE_MODE)


@app.route("/profile", methods=["GET"])
def profile():
    """个人中心（仅限当前登录用户查看本人资料）"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    # 从 session 获取当前登录用户名，查询对应的用户 ID
    current_user = USERS.get(username)
    if not current_user:
        return redirect("/login")

    user_id = current_user["id"]
    user_data = USERS_BY_ID.get(user_id)

    if not user_data:
        return render_template("profile.html", error="未找到该用户！")

    # 排除密码字段传到前端
    display_data = {k: v for k, v in user_data.items() if k != "password"}
    return render_template("profile.html", user=display_data)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值接口（需登录，仅可操作本人账户，金额必须为正数）"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    # CSRF Token 验证
    if not validate_csrf_token():
        print(f"[CSRF-拦截] 充值请求 Token 无效: {username}")
        return redirect("/profile")

    current_user = USERS.get(username)
    if not current_user:
        return redirect("/login")

    user_id = current_user["id"]
    amount = request.form.get("amount", type=float)

    # 金额必须为正数
    if not amount or amount <= 0:
        return redirect(f"/profile")

    # 修改余额
    USERS_BY_ID[user_id]["balance"] += amount
    print(f"[充值] 用户 {username} 充值 {amount}，新余额: {USERS_BY_ID[user_id]['balance']}")

    return redirect(f"/profile")


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码（CSRF 保护已启用）"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    # CSRF Token 验证
    if not validate_csrf_token():
        print(f"[CSRF-拦截] 修改密码请求 Token 无效: {username}")
        return redirect("/profile")

    target_user = request.form.get("username", "")
    new_password = request.form.get("new_password", "")

    if target_user in USERS and new_password:
        # 直接更新密码哈希
        USERS[target_user]["password"] = generate_password_hash(new_password)
        print(f"[修改密码] 用户 {username} 将 {target_user} 的密码修改为: {new_password}")

    return redirect("/profile")


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """URL 抓取功能（不做任何协议/IP 限制）"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    # CSRF Token 验证
    if not validate_csrf_token():
        print(f"[CSRF-拦截] URL抓取请求 Token 无效: {username}")
        return render_template("index.html", fetch_error="安全验证失败，请重试！",
                               user={k: v for k, v in USERS[username].items() if k != "password"},
                               vulnerable_mode=VULNERABLE_MODE)

    url = request.form.get("url", "")
    if not url:
        return render_template("index.html", fetch_error="请输入 URL！",
                               user={k: v for k, v in USERS[username].items() if k != "password"},
                               vulnerable_mode=VULNERABLE_MODE)

    # SSRF 防御①：只允许 http/https 协议
    if not url.lower().startswith(('http://', 'https://')):
        print(f"[SSRF-拦截] 用户 {username} 尝试使用非 http/https 协议: {url}")
        return render_template("index.html", fetch_error="仅支持 http:// 和 https:// 协议的 URL！",
                               user={k: v for k, v in USERS[username].items() if k != "password"},
                               vulnerable_mode=VULNERABLE_MODE)

    # SSRF 防御②：解析 URL 并检查目标 IP
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname

    # 防御 2a：禁止访问内网/回环地址的关键词
    blocked_hosts = {'localhost', '127.0.0.1', '0.0.0.0', '[::1]', '::1'}
    if hostname and hostname.lower() in blocked_hosts:
        print(f"[SSRF-拦截] 用户 {username} 尝试访问内网地址: {url}")
        return render_template("index.html", fetch_error="不允许访问该地址！",
                               user={k: v for k, v in USERS[username].items() if k != "password"},
                               vulnerable_mode=VULNERABLE_MODE)

    # 防御 2b：解析 IP 地址，检查是否为内网 IP
    try:
        import socket
        ip = socket.gethostbyname(hostname)
        # 检查私有 IP 范围
        if ip.startswith('10.') or ip.startswith('192.168.') or ip == '127.0.0.1' or ip == '0.0.0.0':
            raise ValueError("内网地址")
        # 检查 172.16-31.x.x
        if ip.startswith('172.'):
            parts = ip.split('.')
            if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                raise ValueError("内网地址")
        print(f"[SSRF] 用户 {username} 请求 {url} → 解析IP: {ip}")
    except ValueError as e:
        print(f"[SSRF-拦截] 用户 {username} 尝试访问内网地址: {url} → {ip}")
        return render_template("index.html", fetch_error="不允许访问内网地址！",
                               user={k: v for k, v in USERS[username].items() if k != "password"},
                               vulnerable_mode=VULNERABLE_MODE)
    except Exception as e:
        print(f"[SSRF] DNS 解析失败: {url} → {e}")

    result_html = ""
    try:
        # 设置超时，防止慢速攻击
        # 直接访问用户提交的 URL（不限制协议、不检查内网）
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        status_code = resp.status
        content = resp.read()
        # 尝试解码，失败则显示二进制长度
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = f"[二进制内容，共 {len(content)} 字节]"

        result_html = f"""
        <div class="fetch-result">
            <h3>✅ 抓取成功</h3>
            <p><strong>目标 URL：</strong>{url}</p>
            <p><strong>状态码：</strong>{status_code}</p>
            <p><strong>响应大小：</strong>{len(content)} 字节</p>
            <hr>
            <pre class="fetch-content">{text[:5000]}</pre>
        </div>
        """
    except urllib.error.HTTPError as e:
        result_html = f"""
        <div class="fetch-result fetch-error">
            <h3>❌ HTTP 错误</h3>
            <p><strong>目标 URL：</strong>{url}</p>
            <p><strong>状态码：</strong>{e.code}</p>
            <p><strong>错误信息：</strong>{e.reason}</p>
        </div>
        """
    except Exception as e:
        result_html = f"""
        <div class="fetch-result fetch-error">
            <h3>❌ 抓取失败</h3>
            <p><strong>目标 URL：</strong>{url}</p>
            <p><strong>错误信息：</strong>{str(e)[:500]}</p>
        </div>
        """

    print(f"[URL抓取] 用户 {username} 请求: {url}")
    return render_template("index.html",
                           fetch_result=result_html,
                           fetch_url=url,
                           user={k: v for k, v in USERS[username].items() if k != "password"},
                           vulnerable_mode=VULNERABLE_MODE)


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 网络诊断（已修复命令注入漏洞）"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        ip = request.form.get("ip", "")

        # 防御①：使用 shlex.quote 对参数进行转义
        import shlex
        safe_ip = shlex.quote(ip)

        # 防御②：使用 shell=False，避免 shell 解析特殊字符
        command = ["ping", "-c", "3", safe_ip]
        print(f"[Ping] 用户 {username} 执行: ping -c 3 {ip} (已安全转义)")

        try:
            output = subprocess.check_output(command, shell=False, timeout=30, stderr=subprocess.STDOUT)
            result = output.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            result = e.output.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            result = "⚠️ 命令执行超时（30秒）"
        except Exception as e:
            result = f"⚠️ 执行错误: {str(e)}"

        return render_template("ping.html", result=result, ip=ip)

    return render_template("ping.html")


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    """XML 数据导入（使用 ElementTree 安全解析，已修复 XXE 漏洞）"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        xml_data = request.form.get("xml_data", "")
        print(f"[XML导入] 用户 {username} 提交 XML 数据")

        # 防御①：拒绝包含 DOCTYPE/ENTITY/SYSTEM 的 XML（XXE 攻击特征检测）
        xxe_patterns = [
            r'<!DOCTYPE', r'<!ENTITY', r'SYSTEM\s+["\']', r'PUBLIC\s+["\']',
        ]
        for pattern in xxe_patterns:
            if re.search(pattern, xml_data, re.IGNORECASE):
                print(f"[XXE-拦截] 用户 {username} 提交的 XML 包含 XXE 特征: {pattern}")
                result = {
                    "status": "error",
                    "message": "XML 包含不安全的 DOCTYPE/ENTITY 定义，已拒绝处理！"
                }
                result_json = json.dumps(result, ensure_ascii=False, indent=2)
                return render_template("xml_import.html", result=result_json, xml_data=xml_data)

        # 防御②：使用 defusedxml 风格的安全解析（禁用外部实体）
        try:
            # 使用 ElementTree 安全解析（设置 resolve_entities=False）
            parser = ET.XMLParser(target=ET.TreeBuilder())
            # Python 3.8+ ElementTree 默认不解析外部实体
            tree = ET.fromstring(xml_data)

            users = []
            for user_elem in tree.findall('.//user'):
                name_elem = user_elem.find('name')
                email_elem = user_elem.find('email')
                name = name_elem.text if name_elem is not None else ''
                email = email_elem.text if email_elem is not None else ''
                users.append({"name": name, "email": email})

            result = {
                "status": "success",
                "count": len(users),
                "users": users
            }
        except ET.ParseError as e:
            result = {
                "status": "error",
                "message": f"XML 解析失败: {str(e)}"
            }
        except Exception as e:
            result = {
                "status": "error",
                "message": f"解析异常: {str(e)}"
            }

        result_json = json.dumps(result, ensure_ascii=False, indent=2)
        print(f"[XML导入] 解析结果: {result}")
        return render_template("xml_import.html", result=result_json, xml_data=xml_data)

    return render_template("xml_import.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
