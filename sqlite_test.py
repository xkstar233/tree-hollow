import sqlite3

from models import User

# 连接到SQLite数据库
# 数据库文件是example.db，如果文件不存在，会自动创建
conn = sqlite3.connect('mind_chain.db')

# 创建一个Cursor对象
cursor = conn.cursor()

# 执行查询语句
cursor.execute("SELECT id, username, is_admin FROM users WHERE username = 'admin';")

# 获取所有结果
results = cursor.fetchall()

# 关闭游标和连接
cursor.close()
conn.close()

# 输出结果
print(results)
