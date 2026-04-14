# models_zk.py —— ZK 公钥白名单（角色可选）
from datetime import datetime
from extensions import db

class ZKIdentity(db.Model):
    __tablename__ = "zk_identities"
    id = db.Column(db.Integer, primary_key=True)
    pubkey_hex = db.Column(db.String(66), unique=True, nullable=False)  # 压缩公钥
    role = db.Column(db.String(32), default="admin")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
