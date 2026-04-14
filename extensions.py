from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate


# 初始化扩展实例
db = SQLAlchemy()
csrf = CSRFProtect()
migrate = Migrate()