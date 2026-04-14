import hashlib
from config import Config
from transformers import BertTokenizer, BertForSequenceClassification
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F
from datetime import datetime
import pytz
import uuid
from functools import wraps
from flask import abort, current_app
from flask_login import current_user
from extensions import db
from models import SupportResource, WarmMessage
import os
import requests
import time
import jieba
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
# ====== 动态匿名ID、限流、攻击检测/消毒、审计日志 ======
import os, time, hmac, hashlib, re, logging
from collections import deque, defaultdict
from flask import request, current_app, g, make_response
import bleach
# ---- 恶意输入检测与消毒（扩展版：分级） ----
import re, bleach


def ensure_anon_seed_cookie():
    """
    若用户无匿名种子cookie，则下发一个；把值放入 g._anon_seed_value。
    在 app.before_request 中调用；在 app.after_request 中把cookie附加到真实响应。
    """
    cookie_name = current_app.config['ANON_ID_COOKIE_NAME']
    seed = request.cookies.get(cookie_name)
    if not seed:
        seed = os.urandom(16).hex()
        g._anon_seed_set_by_server = True
        g._anon_seed_value = seed
    else:
        g._anon_seed_value = seed

def get_ephemeral_user_id(scope="post"):
    """
    生成“作用域+时间片”稳定的匿名ID（时间片到期自动轮换）：
      - scope: 'post' / 'comment' / 'emergency' / 'chat' 等
    """
    secret = (current_app.config.get('ANON_ID_SECRET') or 'dev-secret').encode()
    seed = getattr(g, "_anon_seed_value", None) or (request.remote_addr or '0.0.0.0')
    ttl_days = int(current_app.config.get('ANON_ID_SCOPE_TTL_DAYS', 1))
    bucket = int(time.time() // (ttl_days * 86400))
    msg = f"{seed}|{scope}|{bucket}".encode()
    digest = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return digest[:16]  # 截短显示即可；也可以用全长

# ---- 内存速率限制（单进程）；生产可换 Redis 方案 ----
_rate_counters = defaultdict(lambda: deque())
def rate_limit_exceeded(key, window_seconds, max_requests):
    now = time.time()
    dq = _rate_counters[key]
    while dq and now - dq[0] > window_seconds:
        dq.popleft()
    if len(dq) >= max_requests:
        return True
    dq.append(now)
    return False

# ---- 恶意输入检测与消毒（扩展版分级） ----

# 分级常量
SEVERITY_CRITICAL = "CRITICAL"  # 可直接导致代码执行/严重注入
SEVERITY_HIGH     = "HIGH"      # 高危读取/绕过/内网探测
SEVERITY_MEDIUM   = "MEDIUM"    # 可疑注入/脚本点
SEVERITY_LOW      = "LOW"       # 低危、噪声

# 规则库（可按需继续扩展）
PATTERNS = {
    # ① XSS（中危）
    "XSS": {
        "severity": SEVERITY_MEDIUM,
        "rules": [
            r"(?i)<\s*script", r"(?i)onerror\s*=", r"(?i)onload\s*=", r"(?i)javascript\s*:",
            r"(?i)srcdoc\s*=", r"(?i)onmouseover\s*=", r"(?i)onfocus\s*="
        ]
    },
    # ② SQL 注入（高危）
    "SQLi": {
        "severity": SEVERITY_HIGH,
        "rules": [
            r"(?i)(\bUNION\b.+\bSELECT\b)", r"(?i)(\bOR\b\s+1=1)", r"(?i)(\bDROP\b\s+\bTABLE\b)",
            r"(?i)(\bINSERT\b\s+INTO\b)", r"(?i)(\bUPDATE\b\s+\w+\s+\bSET\b)", r"(?i)(\bSLEEP\s*\()"
        ]
    },
    # ③ 命令注入 / RCE（致命）
    "RCE": {
        "severity": SEVERITY_CRITICAL,
        "rules": [
            r"(?i)(;|\|\||&&)\s*(cat|ls|whoami|id|dir|type|netstat|curl|wget)\b",
            r"(?i)\$\(.*\)", r"`.+?`", r"(?i)\bsh\s+-c\b", r"(?i)\bpython\s+-c\b", r"(?i)\bpowershell\b"
        ]
    },
    # ④ 路径/文件穿越（高危）
    "Traversal": {
        "severity": SEVERITY_HIGH,
        "rules": [
            r"\.\./", r"\.\.\\", r"(?i)/etc/passwd", r"(?i)\\windows\\system32", r"(?i)\bweb\.config\b",
            r"(?i)\b\.\w{0,3}\.php\b", r"(?i)\.htaccess"
        ]
    },
    # ⑤ SSRF（高危：内网/云元数据等）
    "SSRF": {
        "severity": SEVERITY_HIGH,
        "rules": [
            r"(?i)\b127\.0\.0\.1\b", r"(?i)\blocalhost\b", r"(?i)\b0\.0\.0\.0\b",
            r"(?i)\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            r"(?i)\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
            r"(?i)\b192\.168\.\d{1,3}\.\d{1,3}\b",
            r"(?i)169\.254\.169\.254",          # 云元数据
            r"(?i)\b(file|gopher|dict|sftp|ftp|ssh)://"
        ]
    },
    # ⑥ 低危噪声
    "Noise": {
        "severity": SEVERITY_LOW,
        "rules": [r"(?i)\bselect\b", r"(?i)\bdrop\b", r"(?i)\bexec\b"]
    }
}

def detect_attack_strings(text):
    """
    返回命中列表：[{ 'type':类别, 'pattern':命中正则, 'severity':等级 }]；无命中则 []
    （兼容现有的调用方式，/demo/attack 与中间件会读取这些字段）
    """
    s = text or ""
    results = []
    for tp, spec in PATTERNS.items():
        sev = spec["severity"]
        for pat in spec["rules"]:
            if re.search(pat, s):
                results.append({"type": tp, "pattern": pat, "severity": sev})
    return results

def sanitize_html(text):
    # 白名单清洗（仅处理 HTML/JS 标签，不做中文敏感词过滤）
    return bleach.clean(
        text or "",
        tags=['b', 'i', 'em', 'strong', 'a', 'br', 'p', 'ul', 'ol', 'li', 'code', 'pre'],
        attributes={'a': ['href', 'title', 'rel']},
        strip=True
    )



def iter_request_payloads():
    if request.args:
        for k, v in request.args.items():
            yield ('args', k, v)
    if request.form:
        for k, v in request.form.items():
            yield ('form', k, v)
    if request.is_json:
        js = request.get_json(silent=True) or {}
        for k, v in js.items():
            yield ('json', k, str(v))
    # 不再对 headers 做检测；需要时单独实现
    #for k in ['User-Agent', 'Referer']:
    #    v = request.headers.get(k)
    #    if v:
    #        yield ('header', k, v)

# ---- 审计/安全事件日志 ----
_security_logger = None
def get_security_logger():
    global _security_logger
    if _security_logger is None:
        _security_logger = logging.getLogger("security_events")
        _security_logger.setLevel(logging.INFO)
        fh = logging.FileHandler(current_app.config['SECURITY_EVENT_LOG'], encoding='utf-8')
        fmt = logging.Formatter('%(asctime)s - %(message)s')
        fh.setFormatter(fmt)
        _security_logger.addHandler(fh)
    return _security_logger

def log_security_event(event_type, detail_dict):
    lg = get_security_logger()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.user_agent.string if request.user_agent else ''
    detail = {**(detail_dict or {}), "ip": ip, "ua": ua, "path": request.path}
    lg.info(f"{event_type} | {detail}")






# 匿名ID生成
def generate_dynamic_id():
    """生成带时间戳的匿名ID"""
    timestamp = int(datetime.utcnow().timestamp())
    random_str = uuid.uuid4().hex[:6]
    return f"anon_{timestamp}_{random_str}"

# 专门的管理员检查装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()  # 需要 current_app
        print(f"[DEBUG] 权限检查 - 用户: {current_user.username}, is_admin: {current_user.is_admin}")
        if not bool(current_user.is_admin):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# 情感分析
class SentimentAnalyzer:
    def __init__(self):
        self.labels = ['negative', 'positive']  # 模型固定顺序
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        model_path = "./models/chinese-emotion"  # 本地下载后的模型路径
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)

        self.model.to(self.device)
        self.model.eval()

    def _default_result(self):
        return {'negative': 0.5, 'positive': 0.5}

    def analyze(self, text):
        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = F.softmax(outputs.logits, dim=1)[0]  # 输出是2类logits → softmax后是2个概率

            return {
                label: round(probs[i].item(), 4)
                for i, label in enumerate(self.labels)
            }

        except Exception as e:
            print(f"情感分析失败: {e}")
            return self._default_result()


# 内容过滤
class ContentFilter:
    def __init__(self):
        self.bad_words = set()
        self.word_sources = {}  # 记录每个敏感词的来源
        self._load_sensitive_words()
        self.ml_threshold = 0.8  # 大模型判定阈值
        self.cache = {}  # 缓存检测结果

    def _load_sensitive_words(self):
        """从sensitive_words文件夹加载所有敏感词文件"""
        sensitive_dir = os.path.join(os.path.dirname(__file__), 'sensitive_words')
        if not os.path.exists(sensitive_dir):
            print(f"Warning: 敏感词目录 {sensitive_dir} 不存在")
            return

        # 支持的文件类型
        valid_extensions = ('.txt', '.csv')

        try:
            for filename in os.listdir(sensitive_dir):
                if filename.endswith(valid_extensions):
                    filepath = os.path.join(sensitive_dir, filename)
                    category = os.path.splitext(filename)[0]  # 获取分类名(不带扩展名)

                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            word = line.strip().lower()
                            if word:  # 忽略空行
                                self.bad_words.add(word)
                                # 记录词语来源
                                self.word_sources[word] = category

            print(f"已加载 {len(self.bad_words)} 个敏感词，来自 {len(os.listdir(sensitive_dir))} 个文件")

        except Exception as e:
            print(f"加载敏感词失败: {e}")

    def contains_sensitive_words(self, text):
        """检测文本中的敏感词并返回详细信息"""
        if not self.bad_words:
            return {'sensitive': False, 'details': []}

        text_lower = text.lower()
        found_words = {}

        for word in self.bad_words:
            if word in text_lower:
                # 按分类记录敏感词
                category = self.word_sources.get(word, '其他')
                if category not in found_words:
                    found_words[category] = []
                found_words[category].append(word)

        if found_words:
            return {
                'sensitive': True,
                'details': found_words,
                'message': f"检测到敏感内容 ({len(found_words)}个分类)"
            }
        return {'sensitive': False, 'details': []}


    async def ml_detect(self, text):
        """调用大模型API进行内容安全检测"""
        if not text.strip():
            return False

        # 检查缓存
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # 使用通义千问的安全检测API
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {Config().QWEN_API_KEY}"
            }

            prompt = f"""请判断以下内容是否包含违规信息(暴力、色情、政治敏感等):
{text}

只需回复一个数字:
0-完全合规
1-可能违规
2-明确违规"""

            data = {
                "model": "qwen-max",
                "input": {"messages": [{"role": "user", "content": prompt}]},
                "parameters": {"result_format": "text"}
            }

            response = requests.post(
                "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
                headers=headers,
                json=data,
                timeout=5
            )
            response.raise_for_status()

            result = response.json()
            score = int(result['output']['text'].strip())

            # 缓存结果(5分钟)
            self.cache[cache_key] = score >= 1
            if score >= 1:
                self._extract_new_keywords(text)  # 分析新敏感词

            return score >= 1

        except Exception as e:
            print(f"大模型检测失败: {e}")
            return False

    def _extract_new_keywords(self, text):
        """使用大模型从违规文本中提取可能的新敏感词"""
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {Config().QWEN_API_KEY}"
            }

            prompt = f"""请从以下违规内容中提取3-5个关键词作为需要过滤的新敏感词:
{text}

只需返回关键词列表，用逗号分隔:"""

            data = {
                "model": "qwen-max",
                "input": {"messages": [{"role": "user", "content": prompt}]},
                "parameters": {"result_format": "text"}
            }

            response = requests.post(
                "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
                headers=headers,
                json=data,
                timeout=5
            )
            response.raise_for_status()

            result = response.json()
            new_words = [w.strip().lower() for w in result['output']['text'].split(',') if w.strip()]

            # 将新词添加到"补充词库.txt"
            supplement_file = os.path.join('sensitive_words', '补充词库.txt')
            with open(supplement_file, 'a', encoding='utf-8') as f:
                for word in new_words:
                    if word not in self.bad_words:
                        f.write(f"{word}\n")
                        self.bad_words.add(word)
                        self.word_sources[word] = '补充词库'
        except Exception as e:
            print(f"更新敏感词库失败: {e}")


    async def contains_sensitive_content(self, text):
        """综合检测敏感内容"""
        if not text.strip():
            return False

        # 先检查本地敏感词库
        text_lower = text.lower()
        for bad_word in self.bad_words:
            if bad_word in text_lower:
                return True

        # 本地库未命中则调用大模型
        return await self.ml_detect(text)

    def filter(self, text):
        """过滤文本中的敏感词"""
        if not self.bad_words:
            return text

        words = text.split()
        for i in range(len(words)):
            word_lower = words[i].lower()
            for bad_word in self.bad_words:
                if bad_word in word_lower:
                    words[i] = '*' * len(words[i])
        return ' '.join(words)



class UserMatcher:
    def __init__(self):
        self.user_posts = {}  # 存储用户所有内容 {user_id: 所有发帖拼接}
        self.vectorizer = TfidfVectorizer(
            tokenizer=lambda text: list(jieba.cut(text)),
            min_df=1,
            max_df=0.95
        )
        self.tfidf_matrix = None
        self.user_ids = []

    def add_user_post(self, user_id, content):
        # 新发帖内容追加到该用户语料
        if user_id in self.user_posts:
            self.user_posts[user_id] += " " + content
        else:
            self.user_posts[user_id] = content

    def fit(self):
        # 最少两个用户才建模
        if len(self.user_posts) < 2:
            print("用户匹配训练跳过：语料太少")
            self.tfidf_matrix = None
            return

        contents = list(self.user_posts.values())
        self.user_ids = list(self.user_posts.keys())

        try:
            self.tfidf_matrix = self.vectorizer.fit_transform(contents)
            print("✅ 用户匹配模型已训练")
        except ValueError as e:
            print(f"用户匹配训练失败: {e}")
            self.tfidf_matrix = None

    def find_similar_users(self, user_id, top_n=3):
        if self.tfidf_matrix is None or user_id not in self.user_ids:
            return []

        index = self.user_ids.index(user_id)
        user_vector = self.tfidf_matrix[index]
        similarities = cosine_similarity(user_vector, self.tfidf_matrix)[0]

        # 获取相似用户索引（除自己外）
        similar_indices = similarities.argsort()[::-1]
        similar_users = [
            (self.user_ids[i], round(similarities[i], 4))
            for i in similar_indices
            if i != index
        ]
        return similar_users[:top_n]

# 初始化实例
content_filter = ContentFilter()
sentiment_analyzer = SentimentAnalyzer()
user_matcher = UserMatcher()


def get_support_resources(category=None, emergency_only=False):
    query = SupportResource.query

    if category:
        query = query.filter_by(category=category)

    if emergency_only:
        query = query.filter_by(is_emergency=True)

    return query.all()


class ChatbotHelper:
    def __init__(self):
        self.config = Config()
        self.sentiment_analyzer = sentiment_analyzer  # 复用现有情感分析
        self.content_filter = content_filter  # 添加内容过滤器引用

    def call_openai(self, messages):
        import openai
        openai.api_key = self.config.OPENAI_API_KEY

        response = openai.ChatCompletion.create(
            model=self.config.OPENAI_MODEL,
            messages=messages,
            temperature=self.config.CHATBOT_TEMPERATURE,
            max_tokens=500
        )
        return response.choices[0].message.content

    def call_wenxin(self, prompt):
        import requests
        url = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.WENXIN_API_KEY}"
        }

        data = {
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.config.CHATBOT_TEMPERATURE
        }
        max_retries = 3
        retry_delay = 2  # 重试间隔时间（秒）
        for attempt in range(max_retries):
            try:
                response = requests.post(url, headers=headers, json=data, timeout=5)
                response.raise_for_status()  # 检查响应状态码
                result = response.json()
                if "result" in result:
                    return result["result"]
                else:
                    raise ValueError("API响应中缺少result字段")
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    print(f"第 {attempt + 1} 次调用文心一言API失败，{retry_delay}秒后重试... 错误信息: {e}")
                    time.sleep(retry_delay)
                else:
                    print(f"文心一言API错误: {e}")
                    return "暂时无法连接文心一言服务"
            except (ValueError, KeyError) as e:
                print(f"API响应解析错误: {e}")
                return "暂时无法连接文心一言服务"

    def call_qwen(self, messages):
        """调用通义千问API"""
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.QWEN_API_KEY}"
            }

            data = {
                "model": self.config.QWEN_MODEL,
                "input": {"messages": messages},
                "parameters": {
                    "result_format": "message",
                    "temperature": self.config.CHATBOT_TEMPERATURE
                }
            }

            response = requests.post(
                self.config.QWEN_API_URL,
                headers=headers,
                json=data,
                timeout=10
            )
            response.raise_for_status()

            result = response.json()
            return result['output']['choices'][0]['message']['content']

        except Exception as e:
            print(f"通义千问API错误: {str(e)}")
            return "暂时无法连接AI服务"

    def generate_response(self, user_input, user_id=None):
        # 情感分析
        sentiment = self.sentiment_analyzer.analyze(user_input)

        # 构建系统提示词
        system_prompt = f"""你是一位专业的心理支持助手，正在为一个匿名心理健康平台服务。
用户情绪分析：积极{sentiment['positive']:.0%} 消极{sentiment['negative']:.0%}
请用温暖、非评判性的语气回应，避免诊断建议。"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}
        ]

        # 根据配置选择API
        if self.config.CHATBOT_PROVIDER == "openai":
            response = self.call_openai(messages)
        elif self.config.CHATBOT_PROVIDER == "wenxin":
            response = self.call_wenxin(user_input)
        elif self.config.CHATBOT_PROVIDER == "qwen":
            response = self.call_qwen(messages)
        else:
            response = "未配置有效的AI服务"
        filtered_response = self.content_filter.filter(response)
        # 内容安全过滤
        return filtered_response




class WarmMessageGenerator:
    def __init__(self):
        self.config = Config()

    def generate_new_messages(self, count=3):
        """调用大模型生成新的暖心语"""
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.WENXIN_API_KEY}"
            }

            prompt = """请生成{count}条温暖人心的鼓励话语，适合对情绪低落的人说。要求：
1. 每条不超过30字
2. 积极正面但不过度乐观
3. 避免使用专业术语
4. 用中文表达

请直接返回生成的语句，每条用换行符分隔，不要编号或其他说明文字。"""

            data = {
                "model": "qwen-max",
                "input": {"messages": [{"role": "user", "content": prompt}]},
                "parameters": {"result_format": "text"}
            }

            response = requests.post(
                self.config.QWEN_API_URL,
                headers=headers,
                json=data,
                timeout=10
            )
            response.raise_for_status()

            generated_messages = [
                msg.strip() for msg in
                response.json()['output']['text'].split('\n')
                if msg.strip()
            ]

            # 保存到数据库
            for msg in generated_messages[:count]:
                if not WarmMessage.query.filter_by(content=msg).first():
                    db.session.add(WarmMessage(
                        content=msg,
                        source='ai',
                        created_at=datetime.utcnow()
                    ))

            db.session.commit()
            return generated_messages[:count]

        except Exception as e:
            print(f"生成暖心语失败: {e}")
            return []

    def get_random_message(self):
        """获取一条随机的暖心语"""
        message = WarmMessage.query.filter_by(is_active=True) \
            .order_by(db.func.random()).first()
        return message.content if message else "你今天看起来很棒！"

# 初始化实例
chatbot_helper = ChatbotHelper()