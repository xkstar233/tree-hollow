from logging.handlers import RotatingFileHandler
from flask import abort
from flask import session
from flask import g
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_login import login_required, current_user, LoginManager, login_user
from extensions import db, csrf
from models import User, Post, Comment, SupportResource, EmergencyLog, UserMatch, db, Diary, WarmMessage
from utils import (
    get_support_resources, chatbot_helper,
    sentiment_analyzer, content_filter,
    generate_dynamic_id, user_matcher,
    admin_required, WarmMessageGenerator,
    #  === 新增 ===
    ensure_anon_seed_cookie, get_ephemeral_user_id,
    rate_limit_exceeded, detect_attack_strings, sanitize_html,
    iter_request_payloads, log_security_event
)
from config import Config
from datetime import datetime
import pytz
from extensions import migrate
import json
import logging
import os
from datetime import datetime
import time
from datetime import datetime as _dt
import json
from urllib.parse import urlparse, urljoin
from flask import make_response, jsonify
from flask import render_template
from blockchain_logger import get_chain_log
import requests  #上区块链
import re
from collections import deque
from flask import render_template, request
#零知识证明
from routes_zk import bp as zk_bp
from zk_guard import require_zk_admin
import models_zk  # 确保 ZKIdentity 被载入
from flask import render_template, request, jsonify, current_app
from extensions import db, csrf
from models import Post, Comment
from models_zk import ZKIdentity
from zk_schnorr import prove_knowledge
#from utils import chain_write  # 如果你有上链封装；没有就先返回 None



# 6.4最新版本
# 独立管理员动作 logger（只记录管理员行为，不记录访问日志）
admin_logger = logging.getLogger('admin_actions')
if not admin_logger.handlers:
    admin_logger.setLevel(logging.INFO)
    fh = RotatingFileHandler(
        Config.ADMIN_ACTION_LOG, maxBytes=2_000_000, backupCount=5, encoding='utf-8'
    )
    fh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    admin_logger.addHandler(fh)
    admin_logger.propagate = False  # 不向上冒泡到 root logger


app = Flask(__name__)
app.config.from_object(Config)
login_manager = LoginManager()
login_manager.init_app(app)

# 未登录访问受保护页面时，跳转到 /login
login_manager.login_view = 'login'
login_manager.login_message = "请先登录以访问该页面"
login_manager.login_message_category = "warning"

# 初始化扩展
login_manager.init_app(app)
db.init_app(app)
csrf.init_app(app)
migrate.init_app(app, db)
warm_message_generator = WarmMessageGenerator()

# 创建数据库表
with app.app_context():
    db.create_all()

    # 标志文件防止重复初始化暖心语
    INIT_FLAG_PATH = os.path.join(os.path.dirname(__file__), 'warm_initialized.flag')
    # 在db.create_all()后面添加初始化数据
    if not os.path.exists(INIT_FLAG_PATH):
        print("⚙️ 正在初始化暖心语...")
        if not WarmMessage.query.first():
            default_messages = [
                "你不孤单，我们都在这里陪着你",
                "每一个艰难的日子都会过去",
                "你的感受很重要，值得被倾听",
                "黑暗之后必有光明",
                "你比自己想象的要坚强",
                "一步一个脚印，慢慢来",
                "你的存在本身就是一种价值",
                "今天的你比昨天更强大",
                "无论多难，你都不是一个人在战斗",
                "每一次挫折，都是成长的垫脚石",
                "你的努力终将化作光芒，照亮前行的路",
                "不要害怕黑暗，因为黎明总会到来",
                "你的每一个小进步，都值得骄傲",
                "风雨过后，天空会更加湛蓝",
                "你的勇气，比你想象的还要强大",
                "每一次坚持，都是对自己的最好回应",
                "无论多难，都要相信自己，你值得拥有更好的未来",
                "你的笑容，就是这个世界最美的风景",
                "不要害怕未知，因为每一步都在带你走向更好的自己",
                "无论多难，都要记得，你有无限的可能",
                "你的每一个梦想，都值得被认真对待",
                "无论多难，都要相信，前方有更美好的风景等着你",
                "未来可期，人间值得"
            ]
            for msg in default_messages:
                db.session.add(WarmMessage(content=msg))
            db.session.commit()
            print(f"✅ 已添加 {len(default_messages)} 条暖心语")
        else:
            print("✅ 暖心语已存在，无需初始化")
        # 创建标志文件
        open(INIT_FLAG_PATH, 'w').close()
    else:
        print("⏩ 跳过暖心语初始化（已完成过）")


    # 初始化心理援助资源（真实可用链接）
    if not SupportResource.query.first():
        resources = [
            SupportResource(
                title="中国科学院心理研究所",
                description="专业心理健康资源平台",
                url="http://www.psych.ac.cn",
                category="自助"
            ),
            SupportResource(
                title="简单心理",
                description="专业心理咨询预约平台",
                url="https://www.jiandanxinli.com",
                category="咨询"
            )
        ]
        db.session.add_all(resources)
        db.session.commit()


# ==== Fabric 网关配置 + 上链工具（新增） ====

FABRIC_GW_URL = os.getenv("FABRIC_GW_URL", "http://127.0.0.1:7071")
# ===== 最近上链记录：从本地审计日志提取 =====


# 解析日志里的 [ONCHAIN] 标记（我们在 chain_write 里打过）
_ONCHAIN_LINE_RE = re.compile(r'\[ONCHAIN\]\s+([A-Z0-9_]+)\s*->\s*txId=([a-fA-F0-9]+)', re.IGNORECASE)
# （可选）解析时间戳，如果你的 logging 格式是 "%Y-%m-%d %H:%M:%S,..." 开头
_TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}[^ ]*)')

def recent_onchain_events(limit: int = 20):
    """
    从 Config.ADMIN_ACTION_LOG 逆序抓取最近 N 条 [ONCHAIN] 记录。
    返回: [{"action": "...", "txId": "...", "ts": "..."}, ...]
    """
    path = Config.ADMIN_ACTION_LOG
    items = deque(maxlen=limit)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        for line in reversed(lines):
            m = _ONCHAIN_LINE_RE.search(line)
            if not m:
                continue
            action, txid = m.group(1), m.group(2)
            ts = None
            tm = _TS_RE.match(line)
            if tm:
                ts = tm.group(1)
            items.appendleft({"action": action, "txId": txid, "ts": ts})
            if len(items) >= limit:
                break
    except FileNotFoundError:
        # 首次运行还没有日志文件时
        pass
    return list(items)


def chain_write(action: str, details: dict | str | None = None) -> str | None:
    """
    向 Fabric 网关写一条日志。成功返回 txId，失败返回 None（不中断业务）。
    """
    payload = {"action": action, "details": details if details is not None else {}}
    tries = 2
    for i in range(tries):
        try:
            r = requests.post(f"{FABRIC_GW_URL}/log", json=payload, timeout=5)
            r.raise_for_status()
            ctype = (r.headers.get("content-type") or "").lower()
            data = r.json() if "application/json" in ctype else {}
            txid = data.get("txId") or data.get("txid") or data.get("TXID")
            if txid:
                logging.getLogger('admin_actions').info(f"[ONCHAIN] {action} -> txId={txid}")
                return txid
            logging.getLogger('admin_actions').warning(f"[ONCHAIN] {action} 返回无 txId: {data}")
            return None
        except Exception as e:
            logging.getLogger('admin_actions').warning(f"[ONCHAIN_FAIL] {action}: {e}")
            if i < tries - 1:
                time.sleep(0.6)
    return None




def is_safe_url(target):
    # 仅允许站内相对路径，避免开放重定向
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target or ''))
    return (test_url.scheme in ('http', 'https')
            and ref_url.netloc == test_url.netloc
            and test_url.path.startswith('/'))

# 用户加载器
"""
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/test_sm4")
def test_sm4():
    from encryption import encrypt_data, decrypt_data
    test_string = "这是国密加密测试内容"
    encrypted = encrypt_data(test_string)
    decrypted = decrypt_data(encrypted)
    return f"原文: {test_string}<br>加密后: {encrypted}<br>解密后: {decrypted}"
"""


@app.template_filter("sh_time")
def sh_time(dt, fmt="%Y-%m-%d %H:%M"):
    if not dt:
        return ""
    sh = pytz.timezone("Asia/Shanghai")
    # 兼容历史上存过的“无 tz”的时间，按 UTC 处理
    if getattr(dt, "tzinfo", None) is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(sh).strftime(fmt)

@app.context_processor
def inject_now():
    # 全站页脚 {{ now.year }} 等，直接就是上海时间
    sh = pytz.timezone("Asia/Shanghai")
    return {"now": datetime.now(sh)}

@app.template_filter("iso_utc")
def iso_utc(dt):
    if not dt:
        return ""
    # 兼容历史上存过的 naive 时间：按 UTC 处理
    if getattr(dt, "tzinfo", None) is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(pytz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@login_manager.user_loader
def load_user(user_id):
    # 特别注意： ID 是字符串类型，不是整数
    print("load_user 被调用，user_id:", user_id)
    return User.query.get(str(user_id))  # 确保类型匹配


# ---- 全局安全中间件：匿名种子、速率限制、基础攻击检测 ----
@app.before_request
def _security_middlewares():
    # 0) 静态资源直接放行
    if request.path.startswith('/static/') or (request.endpoint == 'static'):
        return

    # 1) 业务白名单 —— 这些端点/路径不做限流也不做攻击检测
    EXEMPT_ENDPOINTS = {'api_content_check', 'chat', 'demo_attack'}
    EXEMPT_PATHS     = {'/api/content/check', '/api/chat', '/demo/attack'}
    if (request.endpoint in EXEMPT_ENDPOINTS) or (request.path in EXEMPT_PATHS):
        ensure_anon_seed_cookie()
        return

    # 2) 匿名 cookie（保留）
    ensure_anon_seed_cookie()

    # 3) 速率限制：仅对写操作；按 “IP:端点” 计数，减少误伤
    if request.method in ['POST', 'PUT', 'PATCH']:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'unknown'
        key = f"{ip}:{request.endpoint or request.path}"
        if rate_limit_exceeded(key, Config.RATE_LIMIT_WINDOW_SECONDS, Config.RATE_LIMIT_MAX_REQUESTS):
            log_security_event("RATE_LIMIT", {"reason": "too_many_requests", "severity": "LOW"})
            # ← 上链（摘要，不含敏感原文）
            try:
                chain_write("SEC_EVENT", {
                    "type": "RATE_LIMIT",
                    "severity": "LOW",
                    "endpoint": request.endpoint,
                    "path": request.path,
                    "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
                })
            except Exception:
                pass
            return ("Too Many Requests", 429)


        # 4) 攻击检测（只检查正文字段，忽略 csrf_token）
        suspicious = []
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        max_sev = None

        # 端点 → “允许检测的字段” 白名单（其余字段一律忽略，避免误报）
        FIELD_WHITELIST = {
            'new_post': {'content'},
            'add_comment': {'content'},
            'reply_comment': {'content'},
            'diary': {'title', 'content'},
        }

        for place, key_name, val in iter_request_payloads():
            if key_name == 'csrf_token':
                continue
            allow = FIELD_WHITELIST.get(request.endpoint)
            if allow is not None and key_name not in allow:
                continue  # 非关注字段不检测
            hits = detect_attack_strings(val)
            if hits:
                suspicious.append({"place": place, "key": key_name, "hits": hits, "sample": (val or "")[:160]})
                for h in hits:
                    if not max_sev or order[h["severity"]] > order[max_sev]:
                        max_sev = h["severity"]

        if suspicious:
            log_security_event("ATTACK_DETECTED", {"suspicious": suspicious, "severity": max_sev or "MEDIUM"})
            # ← 上链（只写摘要：命中条数/严重度/端点/IP，不上原文）
            try:
                chain_write("SEC_EVENT", {
                    "type": "ATTACK_DETECTED",
                    "severity": max_sev or "MEDIUM",
                    "endpoint": request.endpoint,
                    "path": request.path,
                    "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
                    "hits": sum(len(it["hits"]) for it in suspicious)
                })
            except Exception:
                pass
            return ("Not Acceptable", 406)

    # 5) GET 检测（默认关闭；需要时把 Config.SECURITY_CHECK_GET_PARAMS = True）
    if getattr(Config, 'SECURITY_CHECK_GET_PARAMS', False) and request.method == 'GET':
        pass



@app.after_request
def _attach_anon_seed_cookie(resp):
    # 若 before_request 中下发过新的 anon_seed，这里把它附加到真实响应
    if hasattr(g, "_anon_seed_set_by_server") and g._anon_seed_set_by_server:
        resp.set_cookie(
            Config.ANON_ID_COOKIE_NAME, g._anon_seed_value,
            max_age=Config.ANON_ID_COOKIE_TTL_DAYS * 86400,
            httponly=True, samesite='Lax', secure=False  # 部署HTTPS后把 secure=True
        )
    return resp





@app.route('/test')
def test():
    return "服务已启动", 200


@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).limit(10).all()
    # 在渲染模板时，需要确保传递了用户权限状态
    return render_template('index.html',
                           posts=posts,
                           user=current_user)

@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    # 按时间倒序分页
    posts = Post.query.order_by(Post.created_at.desc()).paginate(page=page, per_page=10)

    # 首屏显示一条暖心语（也可用 JS 再拉接口刷新）
    warm_first = warm_message_generator.get_random_message()
    return render_template(
        'home.html',
        posts=posts,
        warm_first=warm_first
    )

# 管理员路由
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # 概览区：仍保留
    recent_posts = Post.query.order_by(Post.created_at.desc()).limit(10).all()
    recent_onchain = recent_onchain_events(limit=10)

    # ZK 面板区需要更长列表
    zk_posts = Post.query.order_by(Post.created_at.desc()).limit(50).all()

    # 审计区：复用刚才的聚合函数（支持 ?hours=24 覆盖）
    hours = request.args.get('hours', 24, type=int)
    audit_ctx = build_audit_context(hours=hours)

    return render_template(
        'admin/dashboard.html',
        recent_posts=recent_posts,
        recent_onchain=recent_onchain,
        zk_posts=zk_posts,
        **audit_ctx
    )



@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or request.form.get('next')  # 兼容GET/POST
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_active:
            login_user(user)
            flash('登录成功', 'success')
            # ✅ 登录成功后返回原目标页（如 /admin）
            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'error')
    return render_template('login.html')

# # 临时调试路由
# @app.route('/debug_admin')
# def debug_admin():
#     user = User.query.filter_by(username='admin').first()
#     return f"""
#     Admin user exists: {user is not None}<br>
#     is_admin: {getattr(user, 'is_admin', False)}<br>
#     Template exists: {os.path.exists(os.path.join(app.template_folder, 'admin/dashboard.html'))}
#     """
#
# @app.route('/userinfo')
# @login_required
# def userinfo():
#     return f"""
#     用户ID: {current_user.id}<br>
#     用户名: {current_user.username}<br>
#     is_admin: {current_user.is_admin}<br>
#     is_authenticated: {current_user.is_authenticated}
#     """


## 配置日志
#logging.basicConfig(
#    filename='admin_actions.log',
#    level=logging.INFO,
#     format='%(asctime)s - %(message)s',
#     encoding = 'utf-8'  #  强制用 UTF‑8 写入
#)


# 区块链
@app.route("/admin/audit/tx/<txid>")
def admin_audit_tx(txid):
    try:
        data = get_chain_log(txid)
        return render_template("admin/admin_audit_tx.html", data=data)
    except Exception as e:
        return render_template("admin/admin_audit_tx.html", data={"ok": False, "err": str(e)})

# 管理员页的“最近上链记录”子页（也可嵌到仪表盘里）
@app.route("/admin/audit/recent", endpoint="admin_recent_onchain")
@login_required
@admin_required
def admin_recent_onchain():
    limit = int(request.args.get("limit", 20))
    items = recent_onchain_events(limit=limit)
    return render_template("admin/admin_recent_onchain.html", items=items)


@app.route('/admin/delete_post/<post_id>', methods=['POST'])
@login_required
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()

    # === 上链登记 ===
    txid = chain_write("DELETE_POST", {
        "post_id": str(post_id),
        "by": getattr(current_user, "username", "admin")
    })
    if txid:
        # ⚠️ 这一行是“最近上链记录”解析的来源
        logging.getLogger('admin_actions').info(f"[ONCHAIN] DELETE_POST -> txId={txid}")
        session['last_txid'] = txid
        flash(f"帖子已删除（链上 Tx: {txid[:12]}…）", "success")
    else:
        flash("帖子已删除（链上登记失败，不影响业务）", "warning")

    return redirect(url_for('admin_view_posts'))



@app.route('/admin/delete_comment/<comment_id>', methods=['POST'])
@login_required
@admin_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # 本地审计日志
    admin_logger.info(
        f"管理员 {current_user.username} 删除了评论 ID: {comment_id} | "
        f"内容: {comment.content[:50]}... | 帖子: {comment.post_id} | 发布时间: {comment.created_at}"
    )

    # 链上存证
    txid = chain_write("DELETE_COMMENT", {
        "comment_id": comment_id,
        "post_id": comment.post_id,
        "by": current_user.username,
        "created_at": str(comment.created_at),
        "snippet": (comment.content or "")[:80]
    })

    db.session.delete(comment)
    db.session.commit()

    msg = '评论已删除'
    if txid:
        msg += f'（链上 txId: {txid[:12]}…）'
    flash(msg, 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))





@app.route('/api/warm_messages/random')
def get_random_warm_message():
    avoid = (request.args.get('avoid') or '').strip()
    # 如果你的 warm_message_generator 支持排除，就用 exclude/avoid 参数；
    # 否则就循环随机直到不同（加一个最大循环次数防止死循环）
    msg = None
    for _ in range(10):
        candidate = warm_message_generator.get_random_message()
        if candidate and candidate.strip() != avoid:
            msg = candidate.strip(); break
    if not msg:
        msg = warm_message_generator.get_random_message()

    resp = make_response(jsonify({"message": msg}))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route('/admin/warm_messages/generate', methods=['POST'])
@admin_required
def generate_warm_messages():
    if not current_user.is_admin:
        abort(403)
    count = request.json.get('count', 3)
    new_messages = warm_message_generator.generate_new_messages(count)

    # 链上存证（仅记录数量与操作者）
    chain_write("WARM_GENERATE", {
        "generated": len(new_messages),
        "by": current_user.username
    })

    return jsonify({
        "success": True,
        "generated": len(new_messages),
        "messages": new_messages
    })


#添加上下文处理器
@app.context_processor
def utility_processor():
    def get_random_warm_message():
        return warm_message_generator.get_random_message()
    return dict(get_random_warm_message=get_random_warm_message)

#创建简单的管理界面查看和管理暖心语
@app.route('/admin/warm_messages')
@login_required
@admin_required           #  新增
def manage_warm_messages():
    messages = WarmMessage.query.order_by(WarmMessage.created_at.desc()).all()
    return render_template('admin/warm_messages.html', messages=messages)

@app.route('/admin/warm_messages/toggle/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def toggle_warm_message(message_id):
    message = WarmMessage.query.get_or_404(message_id)
    message.is_active = not message.is_active
    db.session.commit()

    # 链上存证（不要把完整文案上链）
    chain_write("WARM_TOGGLE", {
        "message_id": message.id,
        "is_active": message.is_active,
        "by": current_user.username
    })

    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"success": True, "is_active": message.is_active})
    flash('状态已切换', 'success')
    return jsonify({"success": True, "is_active": message.is_active})

# 添加管理帖子的路由
@app.route('/admin/posts')
@login_required
@admin_required
def admin_view_posts():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.created_at.desc()).paginate(page=page, per_page=20)
    return render_template('admin/posts.html', posts=posts)

@app.route('/post/new', methods=['GET', 'POST'])
async def new_post():
    if request.method == 'POST':
        content = request.form.get('content', '').strip()

        # 1. 基础检查
        if not content:
            flash('内容不能为空', 'error')
            return redirect(url_for('new_post'))

        # 2. 敏感内容检测 (多分类检测)
        sensitive_result = content_filter.contains_sensitive_words(content)

        # 3. 大模型深度检测 (只有本地检测通过才进行)
        if not sensitive_result['sensitive']:
            try:
                if await content_filter.ml_detect(content):
                    sensitive_result = {
                        'sensitive': True,
                        'details': {'AI识别': ['潜在敏感内容']},
                        'message': 'AI检测到潜在敏感内容'
                    }
            except Exception as e:
                print(f"大模型检测失败: {e}")
                # 失败时仅记录日志，不阻止发帖

        # 4. 处理敏感内容
        if sensitive_result['sensitive']:
            # 生成详细的分类提示
            details = []
            for category, words in sensitive_result['details'].items():
                displayed_words = words[:3]  # 每类最多显示3个词
                more_count = len(words) - 3
                detail = f"{category}: {', '.join(displayed_words)}"
                if more_count > 0:
                    detail += f" 等{len(words)}个词"
                details.append(detail)

            flash_message = f"内容包含敏感信息: {'; '.join(details)}"
            if len(details) > 1:
                flash_message += f" (共{len(sensitive_result['details'])}个分类)"

            flash(flash_message, 'error')
            return redirect(url_for('new_post'))

        # 5. 情感分析和帖子创建
        try:
            # 情感分析
            sentiment = sentiment_analyzer.analyze(content)

            # 创建帖子 (不自动过滤，因为已经在前端提示)
            post = Post(
                content=content,
                sentiment_data=json.dumps(sentiment),
                # 替换user_id=generate_dynamic_id()
                user_id=get_ephemeral_user_id(scope="post"),
                encrypted=True
            )
            db.session.add(post)
            db.session.commit()

            # 6. 用户匹配功能 (保留原有逻辑)
            if len(content) >= 10:
                user_matcher.add_user_post(post.user_id, content)
                user_matcher.fit()

            flash('发布成功', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'发布失败: {str(e)}', 'error')
            return redirect(url_for('new_post'))

    # GET请求渲染模板
    return render_template('new_post.html')


@app.route('/api/content/check', methods=['POST'])
@csrf.exempt
async def api_content_check():
    """供前端调用的内容检测API(支持多分类敏感词)"""
    data = request.get_json()
    content = data.get('content', '').strip()

    result = {
        'is_sensitive': False,
        'message': '',
        'details': {}
    }

    if not content:
        return jsonify(result)

    # 1. 本地敏感词检测
    sensitive_result = content_filter.contains_sensitive_words(content)
    if sensitive_result['sensitive']:
        result.update({
            'is_sensitive': True,
            'details': sensitive_result['details'],
            'message': sensitive_result['message']
        })
        return jsonify(result)

    # 2. 大模型检测 (只有本地检测通过才进行)
    try:
        if await content_filter.ml_detect(content):
            result.update({
                'is_sensitive': True,
                'details': {'AI识别': ['潜在敏感内容']},
                'message': 'AI检测到潜在敏感内容'
            })
    except Exception as e:
        print(f"API检测失败: {e}")

    return jsonify(result)


@app.route('/post/<post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.created_at.desc()).all()

    # 查找相似用户（增加错误处理）
    similar_users = []
    try:
        similar_users = user_matcher.find_similar_users(post.user_id)
    except Exception as e:
        print(f"查找相似用户错误: {e}")

    return render_template('view_post.html',
                         post=post,
                         comments=comments,
                         similar_users=similar_users)


@app.route('/post/<post_id>/comment', methods=['POST'])
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content', '').strip()

    if not content:
        flash('评论内容不能为空', 'error')
        return redirect(url_for('view_post', post_id=post.id))

    # 敏感词检测
    sensitive_result = content_filter.contains_sensitive_words(content)
    if sensitive_result['sensitive']:
        details = [f"{cat}: {', '.join(words[:3])}{'...' if len(words) > 3 else ''}"
                   for cat, words in sensitive_result['details'].items()]
        flash(f"评论包含敏感内容: {'; '.join(details)}", 'error')
        return redirect(url_for('view_post', post_id=post.id))

    try:
        comment = Comment(
            content=content_filter.filter(content),  # 过滤敏感词
            # 替换user_id=generate_dynamic_id()
            user_id=get_ephemeral_user_id(scope="comment"),
            post_id=post.id,
            parent_id=None
        )
        db.session.add(comment)
        db.session.commit()
        flash('评论添加成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'评论失败: {str(e)}', 'error')

    return redirect(url_for('view_post', post_id=post.id))


@app.route('/post/<post_id>/comment/<parent_id>', methods=['POST'])
def reply_comment(post_id, parent_id):
    post = Post.query.get_or_404(post_id)
    parent = Comment.query.get_or_404(parent_id)
    content = request.form.get('content', '').strip()

    if not content:
        flash('回复内容不能为空', 'error')
        return redirect(url_for('view_post', post_id=post.id))

    # 敏感词检测
    sensitive_result = content_filter.contains_sensitive_words(content)
    if sensitive_result['sensitive']:
        details = [f"{cat}: {', '.join(words[:3])}{'...' if len(words) > 3 else ''}"
                   for cat, words in sensitive_result['details'].items()]
        flash(f"回复包含敏感内容: {'; '.join(details)}", 'error')
        return redirect(url_for('view_post', post_id=post.id))

    try:
        comment = Comment(
            content=content_filter.filter(content),  # 过滤敏感词
            # 替换user_id=generate_dynamic_id()
            user_id=get_ephemeral_user_id(scope="comment"),
            post_id=post.id,
            parent_id=parent.id
        )
        db.session.add(comment)
        db.session.commit()
        flash('回复成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'回复失败: {str(e)}', 'error')

    return redirect(url_for('view_post', post_id=post.id))


@app.route('/resources')
def resources():
    resources = get_support_resources()
    emergency_resources = get_support_resources(emergency_only=True)
    return render_template('resources.html',
                           resources=resources,
                           emergency_resources=emergency_resources)


@app.route('/emergency', methods=['GET', 'POST'])
def emergency():
    if request.method == 'POST':
        # 记录紧急求助
        emergency_log = EmergencyLog(
            # 替换user_id=generate_dynamic_id()
            user_id=get_ephemeral_user_id(scope="emergency"),
            ip_address=request.remote_addr,
            timestamp=datetime.utcnow()
        )
        db.session.add(emergency_log)
        db.session.commit()

        # 返回紧急联系方式
        emergency_resources = get_support_resources(emergency_only=True)
        return render_template('emergency.html', resources=emergency_resources)

    return render_template('emergency_confirm.html')


@app.route('/api/posts')
def api_posts():
    posts = Post.query.order_by(Post.created_at.desc()).limit(20).all()
    return jsonify([{
        'id': post.id,
        'content': post.content,
        'sentiment_score': post.sentiment_score,
        'created_at': post.created_at.isoformat(),
        'comment_count': len(post.comments)
    } for post in posts])


@app.route('/chatbot')
def chatbot():
    if not Config.CHATBOT_ENABLED:
        abort(404)
    return render_template('chatbot.html')


@app.route('/api/support_resources')
def api_support_resources():
    category = request.args.get('category')
    emergency_only = request.args.get('emergency_only', 'false').lower() == 'true'
    resources = get_support_resources(category=category, emergency_only=emergency_only)
    return jsonify([resource.to_dict() for resource in resources])


@app.route('/api/chat', methods=['POST'])
@csrf.exempt
def chat():
    data = request.get_json()
    user_input = data.get('message', '').strip()
    history = data.get('history', [])  # 获取历史对话

    if not user_input:
        return jsonify({"error": "消息不能为空"}), 400

    try:
        response = chatbot_helper.generate_response(
            user_input,
            # 替换user_id=generate_dynamic_id()
            user_id=get_ephemeral_user_id(scope="chat")
        )
        return jsonify({
            "response": response,
            "history": history + [user_input, response]  # 返回更新后的历史
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/test_api')
def test_api():
    test_messages = [
        {"role": "system", "content": "你是一个心理支持助手"},
        {"role": "user", "content": "我今天感到非常焦虑"}
    ]
    response = chatbot_helper.call_openai(test_messages)
    return f"API测试响应: {response}"

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')


# 添加日记本路由

@app.route('/diary', methods=['GET', 'POST'])
def diary():
    # 使用cookie识别用户
    user_id = request.cookies.get('user_id') or generate_dynamic_id()

    if request.method == 'POST':
        title = request.form.get('title', '').strip() or "无标题日记"
        content = request.form.get('content', '').strip()

        if not content:
            flash('日记内容不能为空', 'error')
            return redirect(url_for('diary'))

        # 敏感内容检测
        sensitive_result = content_filter.contains_sensitive_words(content)
        if sensitive_result['sensitive']:
            flash('日记包含敏感内容，请修改后重新提交', 'error')
            return redirect(url_for('diary'))

        try:
            # 情感分析
            sentiment = sentiment_analyzer.analyze(content)

            diary = Diary(
                title=title,
                content=content,
                user_id=user_id,
                sentiment_data=json.dumps(sentiment),
                encrypted=True
            )
            db.session.add(diary)
            db.session.commit()

            flash('日记保存成功', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'保存失败: {str(e)}', 'error')

        return redirect(url_for('diary'))

    # GET请求 - 显示日记列表和编辑器
    # GET请求 - 显示日记列表和编辑器
    diaries = Diary.query.filter_by(user_id=user_id).order_by(Diary.updated_at.desc()).all() or []

    resp = make_response(render_template('diary.html', diaries=diaries))
    # 设置cookie，有效期1年
    resp.set_cookie('user_id', user_id, max_age=31536000)
    return resp


@app.route('/diary/<diary_id>', methods=['GET', 'POST'])
def view_diary(diary_id):
    diary = Diary.query.get_or_404(diary_id)
    user_id = request.cookies.get('user_id')

    if not user_id or diary.user_id != user_id:
        abort(403)  # 禁止访问

    if request.method == 'POST':
        # 更新日记
        title = request.form.get('title', '').strip() or "无标题日记"
        content = request.form.get('content', '').strip()

        if not content:
            flash('日记内容不能为空', 'error')
            return redirect(url_for('view_diary', diary_id=diary.id))

        try:
            diary.title = title
            diary.content = content
            diary.sentiment_data = json.dumps(sentiment_analyzer.analyze(content))
            db.session.commit()
            flash('日记更新成功', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'更新失败: {str(e)}', 'error')

        return redirect(url_for('view_diary', diary_id=diary.id))

    return render_template('view_diary.html', diary=diary)


@app.route('/diary/<diary_id>/delete', methods=['POST'])
def delete_diary(diary_id):
    diary = Diary.query.get_or_404(diary_id)
    user_id = request.cookies.get('user_id')

    if not user_id or diary.user_id != user_id:
        abort(403)

    try:
        db.session.delete(diary)
        db.session.commit()
        flash('日记已删除', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'error')

    return redirect(url_for('diary'))


from extensions import csrf
from flask import render_template_string

# ---- 攻击防御演示页：/demo/attack ----
@app.route('/demo/attack', methods=['GET', 'POST'])
def demo_attack():
    detection = None
    cleaned = None
    raw = ""
    moderation = None

    if request.method == 'POST':
        raw = request.form.get('payload', '') or ''
        hits = detect_attack_strings(raw)
        detection = hits  # list[dict] or []
        cleaned = sanitize_html(raw)
        # 记录最大 severity
        if hits:
            order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            max_sev = max((h["severity"] for h in hits), key=lambda s: order[s])
            log_security_event("DEMO_DETECTED", {"hits": hits, "sample": raw[:200], "severity": max_sev})
            # ← 上链摘要
            try:
                chain_write("SEC_EVENT_DEMO", {
                    "severity": max_sev,
                    "hits": len(hits)
                })
            except Exception:
                pass

        # （可选）内容审核演示
        try:
            moderation = content_filter.contains_sensitive_words(raw)
        except Exception:
            moderation = None

    html = """
    {% extends "base.html" %}
    {% block content %}
    <div class="container my-4">
      <div class="card">
        <div class="card-header bg-warning text-dark">
          <h5>攻击防御演示（XSS/SQLi/RCE/LFI/SSRF）</h5>
        </div>
        <div class="card-body">
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <div class="mb-3">
              <label class="form-label">测试输入</label>
              <textarea name="payload" class="form-control" rows="4" placeholder="示例：<img src=x onerror=alert(1)>、' OR 1=1 --、../../etc/passwd、curl http://169.254.169.254">{{ raw }}</textarea>
            </div>
            <button class="btn btn-primary" type="submit">提交演示</button>
          </form>

          {% if detection is not none %}
          <hr/>
          <h6 class="text-info">检测结果（安全防护）：</h6>
          {% if detection %}
            <ul>
              {% for h in detection %}
                {% set tp = h.type if h.type is defined else h[0] %}
                {% set pat = h.pattern if h.pattern is defined else h[1] %}
                {% set sev = h.severity if h.severity is defined else 'MEDIUM' %}
                <li>
                  <span class="badge bg-danger" style="background-color:{% if sev=='CRITICAL' %}#c0392b{% elif sev=='HIGH' %}#e67e22{% elif sev=='MEDIUM' %}#2980b9{% else %}#7f8c8d{% endif %};">{{ sev }}</span>
                  <code>{{ tp }}</code> 命中：<code>{{ pat }}</code>
                </li>
              {% endfor %}
            </ul>
          {% else %}
            <div class="alert alert-success">未检测到可疑模式。</div>
          {% endif %}

          <h6 class="text-info mt-3">消毒后回显：</h6>
          <div class="border rounded p-3 bg-light">{{ cleaned|safe if cleaned else '' }}</div>
          <small class="text-muted">（bleach 白名单清洗，仅处理 HTML/JS 标签，不做中文词过滤）</small>

          {% if moderation is not none %}
            <h6 class="text-info mt-4">内容审核结果（自伤/辱骂等）：</h6>
            {% if moderation.sensitive %}
              <div class="alert alert-warning">
                检测到敏感内容：
                <ul class="mb-0">
                  {% for cat, words in moderation.details.items() %}
                    <li>{{ cat }}：{{ ', '.join(words[:3]) }}{% if words|length > 3 %} 等{{ words|length }}词{% endif %}</li>
                  {% endfor %}
                </ul>
              </div>
            {% else %}
              <div class="alert alert-success">未检测到敏感内容。</div>
            {% endif %}
          {% endif %}
          {% endif %}
        </div>
      </div>
    </div>
    {% endblock %}
    """
    return render_template_string(html, detection=detection, cleaned=cleaned, raw=raw, moderation=moderation)



# 合并admin界面
def build_audit_context(hours: int = 24):
    hours = max(1, min(int(hours or 24), 168))
    now = _dt.now()
    start_ts = now - timedelta(hours=hours)

    # === 与 /admin/audit 中相同的工具函数与解析流程 ===
    def _tail(path, max_lines=5000):
        import os
        if not os.path.exists(path):
            return []
        with open(path, 'rb') as f:
            data = f.read()
        for enc in ('utf-8', 'gbk', 'latin-1'):
            try:
                text = data.decode(enc); break
            except UnicodeDecodeError:
                continue
        else:
            text = data.decode('utf-8', errors='ignore')
        return text.splitlines()[-max_lines:]

    def _parse_ts(ts_str):
        for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return _dt.strptime(ts_str, fmt)
            except Exception:
                pass
        return None

    def _hour_floor(dt):
        return dt.replace(minute=0, second=0, microsecond=0)

    admin_lines = _tail(Config.ADMIN_ACTION_LOG, 8000)
    sec_lines   = _tail(Config.SECURITY_EVENT_LOG, 8000)

    def _parse_admin(line):
        try:
            ts_str, msg = line.split(" - ", 1)
            ts = _parse_ts(ts_str.strip())
            return {"time": ts_str, "ts": ts, "msg": msg}
        except Exception:
            return {"time": "", "ts": None, "msg": line}

    def _parse_sec(line):
        try:
            ts_str, rest = line.split(" - ", 1)
            ts = _parse_ts(ts_str.strip())
            evt, payload = rest.split(" | ", 1)
            data = None
            if payload.strip().startswith("{") and payload.strip().endswith("}"):
                data = eval(payload)  # 演示用；正式环境请改 json.loads
            return {"time": ts_str, "ts": ts, "event": evt.strip(), "data": data}
        except Exception:
            return {"time": "", "ts": None, "event": "PARSE_ERROR", "data": {"raw": line}}

    admin_items_all = [_parse_admin(ln) for ln in admin_lines]
    sec_items_all   = [_parse_sec(ln)   for ln in sec_lines]

    admin_items = [it for it in admin_items_all if it["ts"] and it["ts"] >= start_ts]
    sec_items   = [it for it in sec_items_all   if it["ts"]   and it["ts"]   >= start_ts]

    # 构造小时轴 & 聚合
    hours_axis = []
    cur = _hour_floor(start_ts)
    end = _hour_floor(now)
    while cur <= end:
        hours_axis.append(cur)
        cur += timedelta(hours=1)

    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    hourly = {h: {lv: 0 for lv in levels} for h in hours_axis}
    for h in hours_axis:
        hourly[h]["ADMIN_ACTION"] = 0

    for it in sec_items:
        h = _hour_floor(it["ts"])
        if h not in hourly:
            continue
        lv = (it.get("data", {}) or {}).get("severity")
        if lv in levels:
            hourly[h][lv] += 1
        elif it.get("event") in ("DEMO_DETECTED", "ATTACK_DETECTED"):
            hourly[h]["MEDIUM"] += 1

    for it in admin_items:
        h = _hour_floor(it["ts"])
        if h in hourly:
            hourly[h]["ADMIN_ACTION"] = hourly[h].get("ADMIN_ACTION", 0) + 1

    labels = [h.strftime("%Y-%m-%d %H") for h in hours_axis]
    color_map = {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#2980b9",
        "LOW": "#7f8c8d", "ADMIN_ACTION": "#2ecc71"
    }
    datasets = []
    for name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ADMIN_ACTION"]:
        datasets.append({
            "label": name,
            "borderColor": color_map[name],
            "data": [hourly[h].get(name, 0) for h in hours_axis]
        })

    return {
        "audit_hours": hours,
        "audit_labels": labels,
        "audit_datasets": datasets,
        "admin_items": admin_items,
        "sec_items": sec_items
    }



# ---- 审计日志可视化：/admin/audit ----
from datetime import datetime as _dt, timedelta
from flask import request, render_template_string

@app.route('/admin/audit')
@login_required
@admin_required
def admin_audit():
    # ====== 1) 读取 hours 参数并约束范围 ======
    try:
        hours = int(request.args.get('hours', 24))
    except Exception:
        hours = 24
    hours = max(1, min(hours, 168))  # 1 ~ 168 小时

    now = _dt.now()
    start_ts = now - timedelta(hours=hours)

    # ====== 工具：读文件 + 解码容错 ======
    def _tail(path, max_lines=5000):
        import os
        if not os.path.exists(path):
            return []
        with open(path, 'rb') as f:
            data = f.read()
        for enc in ('utf-8', 'gbk', 'latin-1'):
            try:
                text = data.decode(enc); break
            except UnicodeDecodeError:
                continue
        else:
            text = data.decode('utf-8', errors='ignore')
        return text.splitlines()[-max_lines:]

    admin_lines = _tail(Config.ADMIN_ACTION_LOG, 8000)
    sec_lines   = _tail(Config.SECURITY_EVENT_LOG, 8000)

    # ====== 解析时间：兼容 2025-08-03 09:43:17,768 或无毫秒 ======
    def _parse_ts(ts_str):
        for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return _dt.strptime(ts_str, fmt)
            except Exception:
                pass
        return None

    def _parse_admin(line):
        # "2025-08-03 09:44:15,780 - 管理员 xxx ..."
        try:
            ts_str, msg = line.split(" - ", 1)
            ts = _parse_ts(ts_str.strip())
            return {"time": ts_str, "ts": ts, "msg": msg}
        except Exception:
            return {"time": "", "ts": None, "msg": line}

    def _parse_sec(line):
        # "2025-08-03 09:43:17,768 - EVENT | {dict}"
        try:
            ts_str, rest = line.split(" - ", 1)
            ts = _parse_ts(ts_str.strip())
            evt, payload = rest.split(" | ", 1)
            data = None
            if payload.strip().startswith("{") and payload.strip().endswith("}"):
                data = eval(payload)   # 演示用；生产建议写 JSON 再 json.loads
            return {"time": ts_str, "ts": ts, "event": evt.strip(), "data": data}
        except Exception:
            return {"time": "", "ts": None, "event": "PARSE_ERROR", "data": {"raw": line}}

    # 解析 + 过滤时间窗口
    admin_items_all = [_parse_admin(ln) for ln in admin_lines]
    sec_items_all   = [_parse_sec(ln)   for ln in sec_lines]

    admin_items = [it for it in admin_items_all if it["ts"] and it["ts"] >= start_ts]
    sec_items   = [it for it in sec_items_all   if it["ts"]   and it["ts"]   >= start_ts]

    # ====== 2) 聚合：按小时桶（start_ts 到 now，每小时一个桶） ======
    def _hour_floor(dt):
        return dt.replace(minute=0, second=0, microsecond=0)

    # 构造完整的 x 轴（每小时）
    hours_axis = []
    cur = _hour_floor(start_ts)
    end = _hour_floor(now)
    while cur <= end:
        hours_axis.append(cur)
        cur += timedelta(hours=1)

    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    # {hour_key: {level: n, 'ADMIN_ACTION': m}}
    hourly = {h: {lv: 0 for lv in levels} for h in hours_axis}
    for h in hours_axis:
        hourly[h]["ADMIN_ACTION"] = 0

    # 安全事件：读取 severity，没有就按 MEDIUM
    for it in sec_items:
        h = _hour_floor(it["ts"])
        if h not in hourly:  # 容错
            continue
        lv = (it.get("data", {}) or {}).get("severity")
        if lv in levels:
            hourly[h][lv] += 1
        elif it.get("event") in ("DEMO_DETECTED", "ATTACK_DETECTED"):
            hourly[h]["MEDIUM"] += 1

    # 管理员行为：计数
    for it in admin_items:
        h = _hour_floor(it["ts"])
        if h in hourly:
            hourly[h]["ADMIN_ACTION"] = hourly[h].get("ADMIN_ACTION", 0) + 1

    labels = [h.strftime("%Y-%m-%d %H") for h in hours_axis]
    color_map = {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#2980b9",
        "LOW": "#7f8c8d", "ADMIN_ACTION": "#2ecc71"
    }
    datasets = []
    for name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ADMIN_ACTION"]:
        datasets.append({
            "label": name,
            "borderColor": color_map[name],
            "data": [hourly[h].get(name, 0) for h in hours_axis]
        })

    # ====== 3) 渲染（上方加小时快捷按钮和输入框） ======
    html = """
    {% extends "base.html" %}
    {% block content %}
    <div class="container my-4">
      <div class="row">
        <div class="col-lg-6">
          <div class="card mb-3">
            <div class="card-header bg-primary text-white">管理员操作日志</div>
            <div class="card-body" style="max-height:420px;overflow:auto;">
              <table class="table table-sm admin-posts-table">
                <thead><tr><th>时间</th><th>详情</th></tr></thead>
                <tbody>
                  {% for it in admin_items|reverse %}
                    <tr><td><small>{{ it.time }}</small></td><td><small>{{ it.msg }}</small></td></tr>
                  {% else %}<tr><td colspan="2">窗口内无管理员日志</td></tr>{% endfor %}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="col-lg-6">
          <div class="card mb-3">
            <div class="card-header bg-info text-white">安全事件日志</div>
            <div class="card-body" style="max-height:420px;overflow:auto;">
              <table class="table table-sm admin-posts-table">
                <thead><tr><th>时间</th><th>事件</th><th>数据</th></tr></thead>
                <tbody>
                  {% for it in sec_items|reverse %}
                    <tr>
                      <td><small>{{ it.time }}</small></td>
                      <td><small><code>{{ it.event }}</code></small></td>
                      <td><small style="white-space:pre-wrap;">{{ it.data }}</small></td>
                    </tr>
                  {% else %}<tr><td colspan="3">窗口内无安全事件</td></tr>{% endfor %}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="col-12">
          <div class="card">
            <div class="card-header bg-secondary text-white"
                style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;">
             <span>近{{ hours }}小时安全事件趋势</span>

             <!-- 强制可见的按钮条 -->
             <div class="audit-toolbar"
                  style="display:flex;align-items:center;gap:.5rem;flex-shrink:0;">
                <a class="btn btn-sm btn-light text-dark" href="{{ url_for('admin_audit', hours=1) }}">1h</a>
                <a class="btn btn-sm btn-light text-dark" href="{{ url_for('admin_audit', hours=6) }}">6h</a>
                <a class="btn btn-sm btn-light text-dark" href="{{ url_for('admin_audit', hours=24) }}">24h</a>
                <a class="btn btn-sm btn-light text-dark" href="{{ url_for('admin_audit', hours=72) }}">72h</a>
                <a class="btn btn-sm btn-light text-dark" href="{{ url_for('admin_audit', hours=168) }}">168h</a>

                <form method="get" style="display:flex;align-items:center;gap:.5rem;margin:0;">
                 <input type="number" min="1" max="168" name="hours" value="{{ hours }}"
                        class="form-control form-control-sm"
                        style="width:90px;background:#fff;color:#000;border:1px solid #ccc;">
                 <button class="btn btn-sm btn-light text-dark" type="submit">应用</button>
                </form>
             </div>
            </div>

            <div class="card-body"><canvas id="secChart" height="120"></canvas></div>
          </div>
        </div>
      </div>
    </div>
    {% endblock %}
    {% block scripts %}
      {{ super() }}
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <script>
        const labels = {{ labels|tojson }};
        const datasets = {{ datasets|tojson }};
        const ctx = document.getElementById('secChart').getContext('2d');
        new Chart(ctx, {
          type: 'line',
          data: {
            labels,
            datasets: datasets.map(ds => ({
              label: ds.label,
              data: ds.data,
              borderColor: ds.borderColor,
              fill: false,
              pointRadius: 2,
              tension: 0.2
            }))
          },
          options: {
            responsive: true,
            plugins: { legend: { position: 'top' } },
            scales: {
              x: { title: { display: true, text: '小时' } },
              y: { title: { display: true, text: '事件数' }, beginAtZero: true, ticks: { precision: 0 } }
            }
          }
        });
      </script>
    {% endblock %}
    """
    return render_template_string(html,
                                  admin_items=admin_items,
                                  sec_items=sec_items,
                                  labels=labels,
                                  datasets=datasets,
                                  hours=hours)



# 受零知识证明保护的管理 API（JSON 调用）
@app.route('/api/admin/delete_post', methods=['POST'])
@csrf.exempt
@require_zk_admin(action="delete_post", resource_field="post_id")
def api_admin_delete_post():
    data = request.get_json(force=True)
    pid = str(data["post_id"])
    post = Post.query.get_or_404(pid)
    db.session.delete(post)
    db.session.commit()
    txid = chain_write("DELETE_POST", {"post_id": pid, "by": "zk-admin"})
    return jsonify({"ok": True, "deleted": pid, "txid": txid})

@app.route('/api/admin/delete_comment', methods=['POST'])
@csrf.exempt
@require_zk_admin(action="delete_comment", resource_field="comment_id")
def api_admin_delete_comment():
    data = request.get_json(force=True)
    cid = str(data["comment_id"])
    comment = Comment.query.get_or_404(cid)
    post_id = str(comment.post_id)
    db.session.delete(comment)
    db.session.commit()
    txid = chain_write("DELETE_COMMENT", {"comment_id": cid, "post_id": post_id, "by": "zk-admin"})
    return jsonify({"ok": True, "deleted": cid, "txid": txid})

# 临时接口：显示当前会话的用户ID
@app.get("/whoami")
def whoami():
    if current_user.is_authenticated:
        return {"auth": True, "user_id": str(current_user.get_id())}
    # 匿名：给一个固定作用域来查看（比如 'whoami'）
    return {"auth": False, "user_id": get_ephemeral_user_id(scope="whoami")}

# 控制面板页面：列出最近 50 条帖子（按时间倒序）
@app.get("/admin/zk_panel")
def admin_zk_panel():
    posts = Post.query.order_by(Post.created_at.desc()).limit(50).all()
    return render_template("admin/zk_panel.html", posts=posts)

# 面板用的“简化 ZK 删除”接口（服务端临时用 SK 生成证明）
@app.post("/api/admin/zk_delete_post")
@csrf.exempt
def api_admin_zk_delete_post():
    data = request.get_json(force=True)
    sk_hex  = (data.get("sk_hex") or "").strip()
    post_id = (data.get("post_id") or "").strip()
    if not sk_hex or not post_id:
        return jsonify({"ok": False, "reason": "sk_hex/post_id required"}), 400

    # 1) 生成一次性消息（绑定操作），服务端生成证明
    import os, time
    nonce = os.urandom(8).hex()
    ts = int(time.time())
    msg = f"delete_post:{post_id}:{nonce}:{ts}"
    proof = prove_knowledge(sk_hex, msg)

    # 2) 白名单校验（公钥必须已注册为 admin）
    pubkey_hex = proof.pubkey_hex
    if not ZKIdentity.query.filter_by(pubkey_hex=pubkey_hex, role="admin").first():
        return jsonify({"ok": False, "reason": "pubkey not allowed"}), 403

    # 3) 真正删除（和 /api/admin/delete_post 的逻辑一致）
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    txid = None
    try:
        txid = chain_write("DELETE_POST", {"post_id": post_id, "by": "zk-admin"})
    except Exception as e:
        current_app.logger.warning("[ONCHAIN_FAIL] %s", e)
        txid = None

    return jsonify({"ok": True, "deleted": post_id, "txid": txid})



csrf.init_app(app)  # 先初始化 CSRF
csrf.exempt(zk_bp)  #/api/zk/*整个蓝图豁免CSRF
# 注册蓝图
app.register_blueprint(zk_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)