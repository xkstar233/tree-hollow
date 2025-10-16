# 在Python shell中
from app import app, db
from models import User


def create_admin():
    with app.app_context():  # 确保在应用上下文中运行
        # 检查是否已存在管理员
        if User.query.filter_by(username='admin').first():
            print("管理员账户已存在")
            return

        # 创建管理员
        admin = User(
            username='admin',
            email='',
            is_admin=True  # 确保User模型有is_admin字段
        )
        admin.set_password('yy123')  # 确保有set_password方法

        db.session.add(admin)
        db.session.commit()
        print("管理员账户创建成功")


if __name__ == '__main__':
    create_admin()
