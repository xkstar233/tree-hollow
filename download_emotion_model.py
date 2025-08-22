from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os

# 新模型地址
model_name = "IDEA-CCNL/Erlangshen-Roberta-110M-Sentiment"
model_dir = "./models/chinese-emotion"
os.makedirs(model_dir, exist_ok=True)

# 下载模型
print(f"正在下载模型：{model_name}")
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# 保存本地
tokenizer.save_pretrained(model_dir)
model.save_pretrained(model_dir)
print(f"✅ 模型已保存到 {os.path.abspath(model_dir)}")

# 验证加载
print("验证模型是否可用...")
tokenizer = AutoTokenizer.from_pretrained(model_dir)
model = AutoModelForSequenceClassification.from_pretrained(model_dir)
print("✅ 本地模型加载成功！")
