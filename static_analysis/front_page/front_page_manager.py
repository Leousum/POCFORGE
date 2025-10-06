import re
import os
import copy
import json
from bs4 import BeautifulSoup

class PageManager():
    def __init__(self, config_file, log_manager) -> None:
        self.config_file = config_file
        self.log_manager = log_manager

# ======================================== Get Method and Form Start ========================================
    def _parse_form(self, form_tag):
        # 解析前端页面中的表单,获取表单内的所有字段名称和可选值首项
        form_field_map = dict()
        if form_tag:
            for input_tag in form_tag.find_all("input", {"type": "text"}):
                form_field_map[input_tag.get("name")] = None
            for select_tag in form_tag.find_all("select"):
                option_value = None
                option_tags = select_tag.find_all("option")
                if option_tags:
                    option_value = option_tags[0].text.strip()
                form_field_map[select_tag.get("name")] = option_value
        return form_field_map

    def _get_files_by_similar_name(self, repo_path: str, target_name: str):
        # 获取仓库中同名文件的路径
        multipath = list()
        if target_name:
            for parent, dirnames, filenames in os.walk(repo_path):
                for filename in filenames:
                    file_path = os.path.join(parent, filename)
                    if file_path.find(target_name) != -1:
                        multipath.append(file_path)
            multipath = list(set(multipath))
        return multipath

    def _get_parameter_mapping(self, tag, parameter):
        parameter_map = dict()
        parameter_map[parameter] = None
        siblings = tag.find_previous_siblings()
        siblings.extend(tag.find_next_siblings())
        for sibling in siblings:
            try:
                sibling_name = sibling.get('name')
                if sibling_name:
                    parameter_map[parameter] = sibling_name.strip()
            except:
                pass
        return parameter_map

    def get_request_method_form(self, repo_path: str, vuln_info: dict):
        # 获取请求方式与表单(注意:在同一文件的同一表单中可能有多个参数可以被注入payload)
        # TODO:这里假设的是同一文件中多个触发漏洞的参数都位于同一表单内,后续看实验结果来决定要不要更改
        origin_parameters = copy.deepcopy(vuln_info["origin_parameters"])
        target_file_name = vuln_info["target_url"]
        method = "GET"
        form_field_map = dict()
        find_method = False
        files_to_analyze = self._get_files_by_similar_name(repo_path, target_file_name)
        for file_path in files_to_analyze:
            if find_method:
                break
            try:
                xml_data = None
                with open(file_path, 'r', encoding='utf-8') as xml_file:
                    xml_data = xml_file.read()
                soup = BeautifulSoup(xml_data, 'html.parser')
                for target_text in origin_parameters:
                    if find_method:
                        break
                    try:
                        reg = re.compile(f'.*{target_text}.*')
                        target_tags = soup.find_all(string = reg)
                        for tag in target_tags:
                            tag = tag.parent
                            if find_method:
                                break
                            try:
                                parameter_map = self._get_parameter_mapping(tag, target_text)
                                for k in parameter_map.keys():
                                    if parameter_map[k]:
                                        vuln_info["vuln_parameters"].append(parameter_map[k])
                                        # 删除掉无用的参数
                                        for i in range(0, len(vuln_info["origin_parameters"])):
                                            if vuln_info["origin_parameters"][i] == k:
                                                vuln_info["origin_parameters"][i] = parameter_map[k]
                                        if k in vuln_info["data"].keys():
                                            del vuln_info["data"][k]
                            except:
                                pass
                            form_tag = tag.find_parent('form')
                            if form_tag:
                                method = form_tag.get('method').upper()
                                form_field_map = self._parse_form(form_tag)
                                find_method = True
                    except Exception as e:
                        raise(e)
            except:
                pass
        vuln_info["method"] = method
        vuln_info["form_parameters"] = list(form_field_map.keys())
        vuln_info["vuln_parameters"] = list(set(vuln_info["vuln_parameters"]))
        for k in form_field_map.keys():
            if k not in vuln_info["data"].keys():
                vuln_info["data"][k] = form_field_map[k]
            else:
                if vuln_info["data"][k] is None:
                    vuln_info["data"][k] = form_field_map[k]
        if vuln_info["vuln_parameters"] == []:
            vuln_info["vuln_parameters"] = origin_parameters
        for parameter in vuln_info["vuln_parameters"]:
            if parameter in vuln_info["data"].keys():
                if vuln_info["vuln_type"] in self.config_file["default_payload"].keys():
                    vuln_info["data"][parameter] = self.config_file["default_payload"][vuln_info["vuln_type"]]
        # 记录日志消息
        if vuln_info["method"]:
            self.log_manager.log_info(f'Find Request Method: {vuln_info["method"]}', False, 2)
        if vuln_info["vuln_parameters"]:
            self.log_manager.log_info(f'Find Vuln Parameters: {", ".join(vuln_info["vuln_parameters"])}', False, 2)
        if vuln_info["form_parameters"]:
            self.log_manager.log_info(f'Find Form Parameters: {", ".join(vuln_info["form_parameters"])}', False, 2)

# ======================================== Get Method and Form End ========================================

# ======================================== Infer Sink Nodes Start ========================================
    def _havaStr(self, text, target_str):
        # 判断字符串中是否含有目标子字符串
        pos = text.find(target_str)
        if pos != -1:
            if (pos - 1) >= 0 and (pos + 1) <= (len(text) - 1):
                flag1 = not text[pos - 1].isalpha()
                flag2 = text[pos - 1] not in ["_", "-", "*", "+"]
                flag3 = not text[pos + len(target_str) + 1].isalpha()
                flag4 = text[pos + len(target_str) + 1] not in ["=", "_", "-", "*", "+"]
                if flag1 and flag2 and flag3 and flag4:
                    return True
        return False

    def _getContent(self, text, start):
        # 从指定位置获取tag内容(找到完全闭合的标签时停止)
        content = text[start]
        brackets = 1
        for pos in range(start + 1, len(text)):
            if brackets == 0:
                break
            content += text[pos]
            if text[pos] in ["<"]: # "&lt;"
                brackets += 1
            elif text[pos] in [">"]: # "&gt;"
                brackets -= 1
        return content

    def _find_nearest_tags(self, text, target_str):
        # 获取目标字符串最近的所有tag列表
        tags = list()
        text = str(text)
        pos = text.find(target_str)
        while pos != -1:
            find_tag = False
            tag_name = ""
            if self._havaStr(text, target_str):
                for i in range(0, pos):
                    j = pos - i - 1
                    if text[j] == "<" and text[j + 1] not in ["/", "?"]:
                        start = j
                        for k in range(start + 1, pos):
                            if text[k] != " ":
                                tag_name += text[k]
                            else:
                                content = self._getContent(text, start)
                                if tag_name != "" and text[start:pos + 1].find("\n") == -1:
                                    if content not in tags:
                                        tags.append(content)
                                find_tag = True
                                break
                    if find_tag:
                        break
            text = text[pos + len(target_str) + 1:]
            pos = text.find(target_str)
        return tags

    def _parseFile(self, file_path):
        # 解析前端页面
        xml_data = None
        with open(file_path, "rb") as f:
            xml_data = f.read().decode('utf8','ignore')
        soup = None
        if file_path.endswith('.xml'):
            soup = BeautifulSoup(xml_data, 'xml')
        else:
            soup = BeautifulSoup(xml_data, 'html.parser')
        tags = soup.find_all(True)
        sections = list()
        if len(tags) >= 2:
            for i in range(len(tags) - 1):
                flag = True
                content1 = str(tags[i])
                for j in range(i + 1, len(tags)):
                    content2 = str(tags[j])
                    if content2.find(content1) != -1:
                        flag = False
                        break
                if flag:
                    sections.append(content1)
        elif len(tags) == 1:
            sections = [str(tags[0])]
        return sections

    def _isPage(self, file_path: str, target_str: str):
        # 判断一个页面是否是前端页面、是否包含目标字符串
        extension_flag = False
        content_flag = False
        extension_names = ['.html','.htm','.shtml','.phtml','.xhtml','.xml','.cshtml',
                        '.php','.php3','.php4','.php5','.php7'
                        '.asp','.aspx','.jsp','.jspx','.erb','.vue','.cfm','.pl','.py','.rb']
        for extension_name in extension_names:
            if file_path.endswith(extension_name):
                extension_flag = True
                break
        if extension_flag:
            xml_data = None
            with open(file_path, "rb") as f:
                xml_data = f.read().decode('utf8','ignore')
            if file_path.endswith('.xml'):
                soup = BeautifulSoup(xml_data, 'xml')
            else:
                soup = BeautifulSoup(xml_data, 'html.parser')
            tags = soup.find_all(True)
            if tags:
                for tag in tags:
                    if str(tag).find(target_str) != -1:
                        content_flag = True
                        break
        return (extension_flag and content_flag)

    def infer_sinks(self, repo_path: str, taint_parameter: str, redirect_url: str):
        # 启发式规则:漏洞的sink点通常在一个前端页面的tag中,且这个tag里面含有taint_parameter
        tag_path_map = dict()
        for parent, dirnames, filenames in os.walk(repo_path):
            for filename in filenames:
                file_path = os.path.join(parent, filename)
                if self._isPage(file_path, taint_parameter):
                    sections = self._parseFile(file_path)
                    for section in sections:
                        tags = self._find_nearest_tags(section, taint_parameter)
                        if tags:
                            for tag in tags:
                                if tag not in tag_path_map.keys():
                                    tag_path_map[tag] = list()
                                if file_path not in tag_path_map[tag]:
                                    tag_path_map[tag].append(file_path)
        if redirect_url is not None:
            flag = False
            new_tag_path_map = dict()
            for tag in tag_path_map.keys():
                new_tag_path_map[tag] = list()
                for file_path in tag_path_map[tag]:
                    if file_path.find(redirect_url) != -1:
                        new_tag_path_map[tag].append(file_path)
                        flag = True
            if flag:
                return new_tag_path_map
        return tag_path_map
                                    
# ======================================== Infer Sink Nodes End ========================================

# ======================================== Find Action Parameter Start ========================================
    def get_action_parameter(self, repo_path: str, vuln_info: dict):
        # 找到action参数(TODO:目前此方法太过简单,需要改善)
        if vuln_info["target_url"] and vuln_info["action"]:
            regex_pattern = vuln_info["target_url"] + "\?.+\=" + vuln_info["action"]
            pattern = re.compile(regex_pattern)
            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            for line in f:
                                match = pattern.search(line)
                                if match:
                                    action_str = re.split(r"\\|\?|&", match.group())
                                    if len(action_str) > 1 and "=" in action_str[1]:
                                        action_parameter = action_str[1].split("=")[0]
                                        vuln_info["action_parameters"].append(action_parameter)
                                        if action_parameter not in vuln_info["data"].keys():
                                            vuln_info["data"][action_parameter] = vuln_info["action"]
                                        else:
                                            if vuln_info["data"][action_parameter] is None:
                                                vuln_info["data"][action_parameter] = vuln_info["action"]
                                        if vuln_info["action_parameters"]:
                                            self.log_manager.log_info(f'Find Action Parameters: {", ".join(vuln_info["action_parameters"])}', False, 2)
                                        return
                    except Exception as e:
                        pass

# ======================================== Find Action Parameter End ========================================