from app import app
from models import Post

with app.app_context():
    print("exists:", bool(Post.query.get("1c99a248-a2ab-42d6-8d24-f501f2b25a00")))
