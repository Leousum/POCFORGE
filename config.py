import os
import json

# 文件路径信息
AUTOPOC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
DATA_ROOT = os.path.join(AUTOPOC_DIR, "temp_data")
REPO_ROOT = os.path.join(AUTOPOC_DIR, "repos")
REPORT_ROOT = os.path.join(AUTOPOC_DIR, "report")
SUMMARY_ROOT = os.path.join(AUTOPOC_DIR, "repos", "summary_root")
QUERY_ROOT = os.path.join(AUTOPOC_DIR, "repos", "query")
LOG_ROOT = os.path.join(AUTOPOC_DIR, "logs")

# Joern配置信息
JOERN_SERVER_POINT = "localhost:8989"
JOERN_WORKSPACE_PATH = os.path.join(DATA_ROOT, 'joern', 'workspace')
JOERN_MAX_QUERY_LIMIT = 2200 # Joern查询次数上限,用于自动重启Joern服务
JOERN_QUERY_ROOT = os.path.join(DATA_ROOT, "query") # CPG查询缓存目录

# 大语言模型配置信息
MODEL = "<your model>"
BASE_URL = "<your base url>"
API_KEY = "<your api key>"

# 建立文件夹
for temp_path in [DATA_ROOT, REPO_ROOT, QUERY_ROOT, JOERN_WORKSPACE_PATH]:
    if not os.path.exists(temp_path):
        os.makedirs(temp_path, mode = 0o777)