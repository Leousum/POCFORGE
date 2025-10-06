import os
import json
import time
from datetime import datetime, timezone, timedelta

from config import LOG_ROOT

class LogManager():
    def __init__(self, source_id: str, vuln_type: str) -> None:
        self.log_root = os.path.join(LOG_ROOT, f"{vuln_type}_{source_id}")
        if not os.path.exists(self.log_root):
            os.makedirs(self.log_root, mode = 0o777)
        self.vuln_type = vuln_type
        self.log_path = os.path.join(self.log_root, f"{vuln_type}_{source_id}.txt")
        self.json_path = os.path.join(self.log_root, f"{vuln_type}_{source_id}.json")
        self.code_path = os.path.join(self.log_root, f"vuln_codes.txt")
        self.cost_path = os.path.join(self.log_root, f"cost.json")
        self.log_cost()
    
    def is_analyzed(self, id):
        '''判断一个节点是否被分析过'''
        if id is not None:
            data = dict()
            with open(self.cost_path, "r", encoding = "utf-8") as cost_file:
                data = json.load(cost_file)
            if "ids" in data.keys():
                if isinstance(data["ids"], list):
                    if id in data["ids"]:
                        return True
        return False

    def log_cost(self, json_key = None, json_content = None):
        '''记录开销'''
        if not os.path.exists(self.cost_path):
            data = dict()
            data["Init memory usage"] = None
            data["Peak memory usage"] = None
            data["total_time"] = 0 # 总的时间开销
            data["construct_cpg_time"] = 0 # 构建CPG图的时间开销
            data["llm_used"] = 0 # 使用LLM的次数
            data["llm_time"] = 0 # 使用LLM的时间开销
            data["llm_question_token"] = 0 # LLM花费token数量
            data["llm_answer_token"] = 0 # LLM回答token数量
            data["static_analysis_time"] = 0 # 静态分析的时间开销
            data["query_count"] = 0
            data["restart_count"] = 0
            data["ids"] = list() # 已处理CPG IDs
            with open(self.cost_path, "w", encoding = "utf-8") as log_file:
                json.dump(data, log_file, ensure_ascii = False, indent = 4)
        if json_key is not None and json_content is not None:
            data = dict()
            with open(self.cost_path, "r", encoding = "utf-8") as cost_file:
                data = json.load(cost_file)
            if json_key not in data.keys():
                data[json_key] = json_content
            else:
                if json_key == "ids":
                    data["ids"].append(json_content)
                elif json_key == ["construct_cpg_time", "query_count"]:
                    data[json_key] = json_content
                elif json_key == ["total_time", "llm_used", "llm_question_token", "llm_answer_token", "restart_count"]:
                    data[json_key] += json_content
                elif json_key in ["llm_time", "static_analysis_time"]:
                    data[json_key] += json_content
                    data["total_time"] += json_content
                else:
                    data[json_key] = json_content
            with open(self.cost_path, "w", encoding = "utf-8") as cost_file:
                json.dump(data, cost_file, ensure_ascii = False, indent = 4)

    def log_info(self, log_content: str, is_title = False, indent_num = 0, log_path = None):
        '''
        记录日志信息
        '''
        # 获取当前UTC时间
        utc_now = datetime.now(timezone.utc)
        # 转成UTC+8时区
        beijing_time = utc_now.astimezone(timezone(timedelta(hours=8)))
        log_content = f'[{beijing_time.strftime("%Y-%m-%d %H:%M:%S")}] {log_content}'
        if is_title:
            log_content = "===================================" + log_content
        else:
            log_content = "|-" + log_content
        for i in range(indent_num):
            log_content = "    " + log_content
        if is_title:
            log_content = log_content + "==================================="
        print(log_content)
        file_path = log_path if log_path is not None else self.log_path
        dir_path = os.path.dirname(file_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, mode = 0o777)
        with open(file_path, "a", encoding = "utf-8") as log_file:
            print(f'{log_content}', file = log_file)
    
    def log_result(self, json_key: str, json_content):
        '''记录中间结果'''
        data = dict()
        if os.path.exists(self.json_path):
            with open(self.json_path, "r", encoding = "utf-8") as log_file:
                data = json.load(log_file)
        data[json_key] = json_content
        with open(self.json_path, "w", encoding = "utf-8") as log_file:
            json.dump(data, log_file, ensure_ascii = False, indent = 4)
    
    def log_codes(self, codes: list, core_codes: list, interest_codes: list):
        '''记录日志信息'''
        with open(self.code_path, "a", encoding = "utf-8") as log_file:
            print(f'==========================================complete code==========================================\n', file = log_file)
        with open(self.code_path, "a", encoding = "utf-8") as log_file:
            print(f'{"".join(codes)}', file = log_file)
        with open(self.code_path, "a", encoding = "utf-8") as log_file:
            print(f'==========================================core code==========================================\n', file = log_file)
        with open(self.code_path, "a", encoding = "utf-8") as log_file:
            print(f'{"".join(core_codes)}', file = log_file)
        with open(self.code_path, "a", encoding = "utf-8") as log_file:
            print(f'==========================================interest code==========================================\n', file = log_file)
        with open(self.code_path, "a", encoding = "utf-8") as log_file:
            print(f'{"".join(interest_codes)}', file = log_file)
    
    def get_log_result(self, json_key: str):
        '''获取日志信息'''
        data = dict()
        if os.path.exists(self.json_path):
            with open(self.json_path, "r", encoding = "utf-8") as log_file:
                data = json.load(log_file)
        if json_key in data.keys():
            return data[json_key]
        return None