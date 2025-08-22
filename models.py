import utcnow

from extensions import db
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import json
import pytz
from flask_login import UserMixin
from encryption import (decrypt_data, encrypt_data)
from sqlalchemy import Column, Integer, String
from sqlalchemy_utils import Timestamp

def _utcnow():
    return datetime.now(pytz.utc)

class User(db.Model, UserMixin):

    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    # 用于匿名匹配的动态ID
    dynamic_id = db.Column(db.String(50), unique=True)
    # 是否活跃，用于登录控制
    _is_active = db.Column('is_active', db.Boolean, default=True)
    # 是否是管理员
    is_admin = db.Column(db.Boolean, default=False) # 确保使用 Boolean
    # 关系字段
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

    # 登录相关方法
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        # 明确返回字符串类型的ID
        return str(self.id)


    def set_admin(self, is_admin=True):
        self.is_admin = is_admin
        db.session.commit()

    def generate_dynamic_id(self):
        from utils import generate_dynamic_id
        self.dynamic_id = generate_dynamic_id()





# 添加Diary模型
class Diary(db.Model):
    __tablename__ = 'diaries'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False, default="无标题日记")
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)
    encrypted = db.Column(db.Boolean, default=True)
    sentiment_data = db.Column(db.Text)  # 存储情感分析结果

    # 与User模型的关系
    author = db.relationship('User', backref=db.backref('diaries', lazy=True, cascade='all, delete-orphan'))

    def get_sentiment(self):
        return json.loads(self.sentiment_data) if self.sentiment_data else None

    # 添加日记加解密方法
    def get_content(self):
        if self.encrypted:
            return decrypt_data(self.content)
        return self.content

    def set_content(self, content):
        self.content = encrypt_data(content)
        self.encrypted = True


class WarmMessage(db.Model):
    __tablename__ = 'warm_messages'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    source = db.Column(db.String(100), default='system')  # system/ai/user
    created_at = db.Column(db.DateTime, default=_utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<WarmMessage {self.id}: {self.content[:20]}...>'


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    content = db.Column(db.Text, nullable=False)
    sentiment_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.now(pytz.utc))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    encrypted = db.Column(db.Boolean, default=True)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    sentiment_data = db.Column(db.Text)  # 存储完整情感分析JSON

    def get_sentiment(self):
        try:
            data = json.loads(self.sentiment_data or '{}')
            return {k: v for k, v in data.items()}
        except Exception:
            return {}


class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # 修改这里
    post_id = db.Column(db.String(36), db.ForeignKey('posts.id'), nullable=False)
    parent_id = db.Column(db.String(36), db.ForeignKey('comments.id'), nullable=True)
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]))
class SupportResource(db.Model):
    __tablename__ = 'support_resources'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500), nullable=False)  # 确保不能为空
    category = db.Column(db.String(50))
    is_emergency = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=_utcnow)  # 新增字段

    def __repr__(self):
        return f'<Resource {self.title}>'

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'url': self.url,
            'category': self.category,
            'is_emergency': self.is_emergency
        }


class EmergencyLog(db.Model):
    __tablename__ = 'emergency_logs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(50))  # 匿名ID
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    handled = db.Column(db.Boolean, default=False)


class UserMatch(db.Model):
    __tablename__ = 'user_matches'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user1_id = db.Column(db.String(50), nullable=False)
    user2_id = db.Column(db.String(50), nullable=False)
    similarity_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=_utcnow)
    last_interacted = db.Column(db.DateTime)