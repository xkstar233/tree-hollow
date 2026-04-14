from sqlalchemy import select
from app import app
from models import Post
from extensions import db

with app.app_context():
    p = db.session.execute(
        select(Post).order_by(Post.created_at.desc())
    ).scalars().first()
    print(p.id if p else None)
