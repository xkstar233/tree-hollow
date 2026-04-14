import schedule
import time
import requests
from config import Config
from utils import content_filter, WarmMessageGenerator
from app import app  # 关键：导入 Flask app 以便使用 app_context

def generate_daily_warm_messages():
    """每天自动生成3条新的暖心语"""
    with app.app_context():  # 确保数据库操作在应用上下文中进行
        generator = WarmMessageGenerator()
        generator.generate_new_messages(3)
        print("✅ 已新增 3 条暖心语")

def update_sensitive_words():
    """每周自动更新敏感词库"""
    try:
        # 1. 从大模型获取最新的敏感词趋势
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {Config.QWEN_API_KEY}"
        }

        data = {
            "model": "qwen-max",
            "input": {
                "messages": [{
                    "role": "user",
                    "content": "请列出2023年最新出现的50个网络敏感词，只需用逗号分隔返回"
                }]
            },
            "parameters": {"result_format": "text"}
        }

        response = requests.post(
            "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
            headers=headers,
            json=data,
            timeout=10
        )
        response.raise_for_status()

        new_words = [
            w.strip().lower()
            for w in response.json()['output']['text'].split(',')
            if w.strip()
        ]

        # 2. 更新本地敏感词库
        existing_words = content_filter.bad_words
        with open('sensitive_words.txt', 'a+', encoding='utf-8') as f:
            for word in new_words:
                if word not in existing_words:
                    f.write(f"\n{word}")
                    existing_words.add(word)

        print(f"✅ 更新了 {len(new_words)} 个新敏感词")

    except Exception as e:
        print(f"❌ 自动更新敏感词失败: {e}")

# 设置定时任务
schedule.every().monday.at("03:00").do(update_sensitive_words)  # 每周一凌晨3点
schedule.every().day.at("02:00").do(generate_daily_warm_messages)  # 每天凌晨2点

if __name__ == '__main__':
    print("⏳ 定时任务已启动…")
    while True:
        schedule.run_pending()
        time.sleep(60)
