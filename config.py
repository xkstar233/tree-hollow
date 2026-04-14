import os
import torch
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

load_dotenv()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'mind_chain.db')
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here-123456')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    AES_KEY = os.getenv('AES_KEY', 'your-32-byte-aes-key-here123456789012').encode('utf-8')
    AES_NONCE = os.getenv('AES_NONCE', 'your-12-byte-nonce').encode('utf-8')
    SENTIMENT_MODEL = os.path.join(BASE_DIR, "models", "bert-base-uncased")
    TORCH_DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY', 'csrf-secret-key-123456')
    SENSITIVE_WORDS_DIR = os.path.join(BASE_DIR, 'sensitive_words')
    # 新增大模型配置
    CHATBOT_ENABLED = True
    CHATBOT_PROVIDER = "qwen"  # 或"openai"或“wenxin"
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL = "gpt-3.5-turbo"
    WENXIN_API_KEY = os.getenv("WENXIN_API_KEY")
    QWEN_API_KEY = os.getenv("QWEN_API_KEY")
    QWEN_API_URL = "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
    QWEN_MODEL = "qwen-turbo"  # 可选 qwen-plus 或 qwen-max
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")  # DeepSeek
    CONTENT_MODERATION_THRESHOLD = 0.7  # 敏感内容判定阈值
    CHATBOT_TEMPERATURE = 0.7  # 控制创造性
    # 单独的管理员日志路径
    ADMIN_ACTION_LOG = os.path.join(BASE_DIR, 'admin_actions.log')
    # === Security / Audit ===
    SECURITY_EVENT_LOG = os.path.join(BASE_DIR, 'security_events.log')
    # 速率限制（按IP）。60秒内最多30次请求
    RATE_LIMIT_WINDOW_SECONDS = 60
    RATE_LIMIT_MAX_REQUESTS = 30
    # 安全检测：对 GET 查询参数也做检测与记录（改为 True，即可连 URL 上的注入也记录在案）
    SECURITY_CHECK_GET_PARAMS = False
    # 动态匿名ID（基于 HMAC 的作用域+时间片轮换）
    ANON_ID_SECRET = os.getenv("ANON_ID_SECRET", "change-this-in-prod")  # 生产环境请改成随机强密钥
    ANON_ID_COOKIE_NAME = "anon_seed"
    ANON_ID_COOKIE_TTL_DAYS = 30
    ANON_ID_SCOPE_TTL_DAYS = 1  # 按“天”为时间片，可改成按小时/周
    #Tor配置
    USE_TOR_FOR_EGRESS = True
    TOR_SOCKS_HOST = "127.0.0.1"
    TOR_SOCKS_PORT = 9150  # 若用 Tor Browser 改为 9150

    # 读取 SM4 密钥
    sm4_key_hex = os.getenv("SM4_KEY")
    if not sm4_key_hex:
        raise ValueError("❌ 环境变量 SM4_KEY 未设置")
    try:
        derived_sm4_key = bytes.fromhex(sm4_key_hex)
    except ValueError:
        raise ValueError("❌ SM4_KEY 不是合法的十六进制字符串")
    if len(derived_sm4_key) != 16:
        raise ValueError("❌ SM4_KEY 必须是 16 字节（32 hex 字符）")

    @property
    def derived_aes_key(self):
        """使用PBKDF2派生更安全的密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
        )
        return kdf.derive(self.AES_KEY)


