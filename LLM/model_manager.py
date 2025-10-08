import json
from openai import OpenAI
# import os
# import sys
# sys.path.append("/home/leousum/AutoPoC")

import config
from utils.log_manager import LogManager

class ModelManager():
    def __init__(self, log_manager: LogManager) -> None:
        self.history = []
        self.model = config.MODEL
        self.base_url = config.BASE_URL
        self.api_key = config.API_KEY
        self.log_manager = log_manager
        self.client = OpenAI(base_url = self.base_url, api_key = self.api_key)

# ======================================== Convert String Start ========================================
    def cut_text(self, gpt_answer, keywords):
        # 根据关键字切割GPT的回答(默认其回答是一个字典而非列表)
        text = gpt_answer
        keyword = None
        for k in keywords:
            if gpt_answer.find(k) != -1:
                keyword = k
        if keyword is not None:
            temp_gpt_answer1 = gpt_answer[:gpt_answer.find(keyword)]
            brace_pos = temp_gpt_answer1.rfind("{")
            if brace_pos != -1:
                temp_gpt_answer2 = gpt_answer[brace_pos - 1:]
                if brace_pos == 0:
                    temp_gpt_answer2 = gpt_answer[brace_pos:]
                start = 0; end = len(temp_gpt_answer2)
                find_brace = False
                brace_num = 0
                for i in range(0, len(temp_gpt_answer2)):
                    item = temp_gpt_answer2[i]
                    if find_brace and brace_num == 0:
                        end = i
                        break
                    if item == "{":
                        if brace_num == 0:
                            start = i
                            find_brace = True
                        brace_num += 1
                    elif item == "}":
                        if find_brace and brace_num > 0:
                            brace_num -= 1
                text = temp_gpt_answer2[start:end]
        return text
    
    def str2dict(self, text):
        '''
        Extract a dictionary from a string
        '''
        text_dict = dict()
        if text.find("{") != -1 and text.rfind("}") != -1:
            text = text[text.find("{"):text.rfind("}") + 1]
            infos = text.split("\n")
            text = "".join(infos).strip()
            try:
                text_dict = json.loads(text)
            except:
                pass
        for k in text_dict.keys():
            if text_dict[k] == "None":
                text_dict[k] = None
        return text_dict

    def str2list(self, text):
        '''
        Extract a list from a string
        '''
        text_list = list()
        try:
            if text.find("[") != -1 and text.rfind("]") != -1:
                text = text[text.find("["):text.rfind("]") + 1]
                infos = text.split("\n")
                text = "".join(infos).strip()
                text_list = json.loads(text)
            for i in range(len(text_list)):
                for k in text_list[i].keys():
                    if text_list[i][k] is not None:
                        if k.lower() in ["baseurl", "target", "action"]:
                            if text_list[i][k].lower() in ["none", ""]:
                                text_list[i][k] = None
                        elif k.lower() == "parameters":
                            for j in range(len(text_list[i][k])):
                                if "value" in text_list[i][k][j].keys():
                                    if text_list[i][k][j]["value"].lower() in ["none", ""] or text_list[i][k][j]["value"].lower().find("payload") != -1:
                                        text_list[i][k][j]["value"] = None
        except:
            text_dict = self.str2dict(text)
            if text_dict != {}:
                text_list.append(text_dict)
        return text_list

# ======================================== Convert String End ========================================

# ======================================== Information Extraction Start ========================================
    def info_extract(self, type, description):
        # 从漏洞描述中提取出baseUrl, Target, Action and Parameters
        self.log_manager.log_info(f'提取漏洞描述信息', True, 0)
        self.log_manager.log_result("description", description)
        example = '[{"baseUrl":"","Target":"","Action":"","Parameters":[{"name":"","value":""}]}]'
        pmt1 = f"""Suppose the {type} vulnerability often has PoC format as : {example}.
        In this template, <baseUrl> should be set to localhost. <Target> represents the target file or module the request sent to(ie:target.php).
        <Action> represents the action related to the poc request. <Parameters> represents the parameters in the request, <name> and <value> 
        represents the name and value of one parameter. When some parameters are vulnerable, the value is often the payload of PoC. 
        Based on the information above, please extract necessary information from the vulnerability description below and fill in the template,
        if some information is missing, you can leave it empty. Your answer should follow this json format: {example}.
        Note, only provides the json, no other words. The vulnerability description is : '{description}' """
        self.log_manager.log_info(f'Question: {pmt1}', False, 1)
        info = self.log_manager.get_log_result("info_extract")
        if info is not None:
            self.log_manager.log_info(f'Answer: {str(info)}', False, 1)
            return info
        result = None
        try_num = 0
        while result is None:
            try:
                try_num += 1
                if try_num > 2:
                    return result
                    break
                self.history.clear()
                self.history.append({
                    "role": "user",
                    "content": pmt1
                })
                chat_completion = self.client.chat.completions.create(
                    messages = self.history,
                    model = self.model,
                )
                if chat_completion.choices[0].message.content:
                    self.history.append({
                        "role": "assistant",
                        "content": chat_completion.choices[0].message.content
                    })
                    self.log_manager.log_info(f'Answer: {chat_completion.choices[0].message.content}', False, 1)
                    result = self.str2list(chat_completion.choices[0].message.content)
                    self.log_manager.log_result("info_extract", result)
            except:
                pass
        return result
# ======================================== Information Extraction End ========================================

# ======================================== Payload Infer Start ========================================

    def infer_inject_position(self, vuln_type, taint, codes):
        # 获取注入的具体位置
        promt = f"""The "{taint}" field in a web application can be used to cause an {vuln_type} attack, the core code is: "{codes}". """
        if vuln_type == "xss":
            promt += f"""Please determine whether the injection point is in an attribute of a tag. If so, extract the tag and attribute. """
            promt += f"""Your answer should be in the format of: "{{"answer": "<yes or no>", "tag":"<the inject position tag or empty>", "attribute":"<the inject position attribute or empty>", "reason":"<your reason>"}}"."""
        elif vuln_type == "sql injection":
            promt += f"""Please determine whether the injection point is in the "WHERE" substatement of a "SELECT" statement. """
            promt += f"""Your answer should be in the format of: "{{"answer": "<yes or no>", "reason":"<your reason>"}}"."""
        elif vuln_type == "directory traversal":
            promt += f"""Please determine what command the injection point affects. """
            promt += f"""Your answer should be in the format of: "{{"answer": "<the inject command name>", "reason":"<your reason>"}}"."""
        else:
            return None
        self.log_manager.log_info(f'Question: {promt}', False, 3)
        result = None
        try_num = 0
        while result is None:
            try:
                try_num += 1
                if try_num > 2:
                    return result
                    break
                self.history.clear()
                self.history.append({
                    "role": "user",
                    "content": promt
                })
                chat_completion = self.client.chat.completions.create(
                    messages = self.history,
                    model = self.model,
                )
                if chat_completion.choices[0].message.content:
                    self.log_manager.log_info(f'Answer: {chat_completion.choices[0].message.content}', False, 3)
                    ans = None
                    gpt_answer = chat_completion.choices[0].message.content
                    try:
                        ans = self.str2dict(gpt_answer)
                    except:
                        try:
                            answer_text = self.cut_text(gpt_answer, ['"answer":', "'answer':"])
                            ans = self.str2dict(answer_text)
                        except Exception as e:
                            raise(e)
                    if isinstance(ans, dict):
                        if "answer" in ans.keys():
                            result = ans
            except Exception as e:
                raise(e)
                pass
        return result
# ======================================== Payload Infer End ========================================

# ======================================== Database Operation TripleS Extraction Start ========================================
    def extract_db_triple(self, code: str, vuln_parameter = None):
        # 提取数据库操作三元组
        vuln_column = ""
        if vuln_parameter:
            vuln_column = f'"vuln_column":"<the field injected by the variable \'{vuln_parameter}\'>",'
        promt = f'''Determine whether the following code contains database operations and extract information about database operations from it. Your answer should be in the format of "{{"answer":"<yes or no>","table":"<table name>","column":["<column name1>","<column name2>"...],{vuln_column}"operation":"<read or write>"}}". The code is shown below:
        {code}'''
        self.log_manager.log_info(f'Question: {promt}', False, 3)
        result = None
        try_num = 0
        while result is None:
            try:
                try_num += 1
                if try_num > 2:
                    return result
                    break
                self.history.clear()
                self.history.append({
                    "role": "user",
                    "content": promt
                })
                chat_completion = self.client.chat.completions.create(
                    messages = self.history,
                    model = self.model,
                )
                if chat_completion.choices[0].message.content:
                    self.history.append({
                        "role": "assistant",
                        "content": chat_completion.choices[0].message.content
                    })
                    self.log_manager.log_info(f'Answer: {chat_completion.choices[0].message.content}', False, 3)
                    ans = None
                    gpt_answer = chat_completion.choices[0].message.content
                    try:
                        ans = self.str2dict(gpt_answer)
                    except:
                        try:
                            answer_text = self.cut_text(gpt_answer, ['"answer":', "'answer':"])
                            ans = self.str2dict(answer_text)
                        except Exception as e:
                            raise(e)
                    if isinstance(ans, dict):
                        if "answer" in ans.keys() and "table" in ans.keys() and "column" in ans.keys() and "operation" in ans.keys():
                            result = ans
            except:
                pass
        return result

    def judge_method_db_opearation(self, code: str, table_name: str, column_name: str):
        # 判断一个函数是否可以读取表中所需列的数据
        promt = f"""The "{table_name}" table contains the "{column_name}" field, please determine whether the following function can read and return the "{column_name}" field from the "{table_name}" table. Your answer should be in the format of "{"answer": "<yes or no>", "reason": "<your reason>"}:
        {code}"""
        self.log_manager.log_info(f'Question: {promt}', False, 3)
        result = None
        try_num = 0
        while result is None:
            try:
                try_num += 1
                if try_num > 2:
                    return result
                    break
                self.history.clear()
                self.history.append({
                    "role": "user",
                    "content": promt
                })
                chat_completion = self.client.chat.completions.create(
                    messages = self.history,
                    model = self.model,
                )
                if chat_completion.choices[0].message.content:
                    self.history.append({
                        "role": "assistant",
                        "content": chat_completion.choices[0].message.content
                    })
                    self.log_manager.log_info(f'Answer: {chat_completion.choices[0].message.content}', False, 3)
                    ans = None
                    gpt_answer = chat_completion.choices[0].message.content
                    try:
                        ans = self.str2dict(gpt_answer)
                    except:
                        try:
                            answer_text = self.cut_text(gpt_answer, ['"answer":', "'answer':"])
                            ans = self.str2dict(answer_text)
                        except Exception as e:
                            raise(e)
                    if isinstance(ans, dict):
                        if "answer" in ans.keys():
                            result = ans
            except:
                pass
        return result

# ======================================== Database Operation Triples Extraction End ========================================