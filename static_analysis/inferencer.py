import os
import sys
import copy
import urllib.parse
cur_path = os.getcwd()
sys.path.append(cur_path + '/static_analysis')
from LLM.model_manager import ModelManager
from joern_manager.joern import JoernServer
from utils.log_manager import LogManager
from taint.poc_analysis import PoCAnalyzer
from front_page.front_page_manager import PageManager
from taint.source_sink_handler import SourceSinkHandler

class InferManager():
    def __init__(self, config_file, model_manager: ModelManager, joern_server: JoernServer, log_manager: LogManager) -> None:
        self.config_file = config_file
        self.model_manager = model_manager
        self.joern_server = joern_server
        self.log_manager = log_manager
        self.page_manager = PageManager(config_file, log_manager)
        self.source_sink_handler = SourceSinkHandler(joern_server, model_manager, log_manager)
        self.taint_manager = PoCAnalyzer(config_file, joern_server, self.page_manager, model_manager, log_manager)
    
    def _find_real_file_name(self, repo_path, target_file_name):
        # 漏洞描述中提取到的url不一定对应实际的文件名称,例如CVE-2022-24223: "/Atom.CMS/admin/login.php"(可能含有项目名称)
        if target_file_name:
            file_names = target_file_name.split("/")
            for item in file_names:
                if not item:
                    file_names.remove(item)
            if file_names:
                for i in range(0, len(file_names)):
                    file_path = repo_path
                    for j in range(i, len(file_names)):
                        file_path = os.path.join(file_path, file_names[j])
                    if os.path.exists(file_path):
                        return os.path.relpath(file_path, repo_path)
            for parent, dirnames, filenames in os.walk(repo_path):
                for dirname in dirnames:
                    dirpath = os.path.join(parent, dirname)
                    file_path = os.path.join(dirpath, target_file_name)
                    if os.path.exists(file_path):
                        return os.path.relpath(file_path, repo_path)
        return None

    def _find_relative_root(self, repo_path, target_file_name):
        # 找到目标文件在组件仓库中的相对目录
        if target_file_name:
            repo_root = os.path.dirname(repo_path)
            file_path = os.path.join(repo_path, target_file_name)
            file_root = os.path.dirname(file_path)
            path_without_root = os.path.relpath(file_root, repo_root)
            if path_without_root != ".":
                return path_without_root
        return None

    def reformat_info(self, vuln_type: str, repo_path: str, gpt_infos: list):
        # 更新信息格式
        vuln_infos = list()
        for gpt_info in gpt_infos:
            vuln_info = dict()
            vuln_info["vuln_type"] = vuln_type
            vuln_info["method"] = None
            vuln_info["base_url"] = "localhost" # 包含了host信息
            vuln_info["target_url"] = None # 触发漏洞的URL
            vuln_info["action"] = None # 描述中提及的action
            vuln_info["origin_parameters"] = list() # 描述中所提及的参数
            vuln_info["action_parameters"] = list() # action相关参数
            vuln_info["vuln_parameters"] = list() # 描述中所提及的参数在程序中所对应的实际参数
            vuln_info["form_parameters"] = list() # 表格中所发送的所有参数
            vuln_info["constraint_parameters"] = list() # 执行污点分析后,整条路径所满足的约束条件中携带的参数
            vuln_info["data"] = dict() # 最后发送请求时传输的数据(其中含有上面提及的所有参数)
            if "baseUrl" in gpt_info.keys():
                if gpt_info["baseUrl"]:
                    vuln_info["base_url"] = gpt_info["baseUrl"]
            if "Target" in gpt_info.keys():
                vuln_info["target_url"] = self._find_real_file_name(repo_path, gpt_info["Target"])
                relative_root = self._find_relative_root(repo_path, vuln_info["target_url"])
                if relative_root is not None:
                    vuln_info["base_url"] = vuln_info["base_url"] + "/" + relative_root
            if "Action" in gpt_info.keys():
                vuln_info["action"] = gpt_info["Action"]
            if "Parameters" in gpt_info.keys():
                for item in gpt_info["Parameters"]:
                    if "name" in item.keys():
                        vuln_info["origin_parameters"].append(item["name"])
                        vuln_info["data"][item["name"]] = None
                        if "value" in item.keys():
                            vuln_info["data"][item["name"]] = item["value"]
            vuln_infos.append(vuln_info)
        self.log_manager.log_result("reformat_info", vuln_infos)
        return vuln_infos

    def have_key(self, parameter, user_input: dict):
        # 判断字典中是否含有某个key
        if parameter in user_input.keys():
            return True
        for k in user_input.keys():
            if isinstance(user_input[k], dict):
                if self.have_key(parameter, user_input[k]):
                    return True
        return False
    
    def get_pos_dict(self, parameter, user_input: dict):
        # 获取目标位置
        if not isinstance(user_input, dict):
            return False, None
        if parameter in user_input.keys():
            return True, user_input
        for k in user_input.keys():
            if isinstance(user_input[k], dict):
                flag, pos_dict = self.get_pos_dict(parameter, user_input[k])
                if flag:
                    return True, pos_dict
        return False, None
    
    def merge_structure(self, user_input: dict, data: dict):
        # 合并结构,将data中的k-v对复制到user_input的结构中
        exist_dict = None
        process_map = dict()
        for k in data.keys():
            process_map[k] = False
        for k in user_input.keys():
            for parameter in data.keys():
                flag, pos_dict = self.get_pos_dict(parameter, user_input[k])
                if flag:
                    exist_dict = pos_dict
                    pos_dict[parameter] = data[parameter]
                    process_map[parameter] = True
        if exist_dict is None:
            if "data" not in user_input.keys():
                user_input["data"] = dict()
            for k in process_map.keys():
                if not process_map[k]:
                    user_input["data"][k] = data[k]
        else:
            for k in process_map.keys():
                if not process_map[k]:
                    exist_dict[k] = data[k]

    def code_analysis(self, vuln_type: str, repo_path: str, gpt_infos: list):
        '''
        Obtain critical information that triggers vulnerabilities through code analysis
        '''
        self.log_manager.log_info(f'Start code analysis...', False, 1)
        self.joern_server.log_level = 1
        vuln_infos = self.reformat_info(vuln_type, repo_path, gpt_infos)
        automated_poc_list = list()
        self.log_manager.log_info(f'Obtain {len(vuln_infos)} vuln_infos!', False, 1)
        find_poc = False
        for i in range(0, len(vuln_infos)):
            if find_poc:
                break
            index1 = f"[{str(i)}]"
            self.log_manager.log_info(f'Processing vuln_infos{index1}', False, 2)
            vuln_info = vuln_infos[i]
            self.joern_server.log_level = 2
            self.page_manager.get_request_method_form(repo_path, vuln_info)
            self.page_manager.get_action_parameter(repo_path, vuln_info)
            self.log_manager.log_result(f"vuln_infos{index1}", vuln_info)
            if vuln_info["vuln_parameters"] != []:
                vuln_parameter = vuln_info["vuln_parameters"][0] # TODO:暂时只拿一个参数进行分析,后续可能需要改动
                infos = self.source_sink_handler.infer_source_cpg_node(vuln_type, vuln_parameter, vuln_info["target_url"], index1)
                self.log_manager.log_info(f'Obtain {len(infos)} source and start infos!', False, 2)
                for j in range(0, len(infos)):
                    if find_poc:
                        break
                    index2 = index1 + f"[{str(j)}]"
                    self.log_manager.log_info(f'Processing Source Cpg Nodes{index2}!', False, 2)
                    start_cpg_node = infos[j]["start_cpg_node"]
                    source_cpg_node = infos[j]["source_cpg_node"]
                    condition_node_dicts = infos[j]["condition_node_dicts"]
                    if source_cpg_node is not None:
                        taint_infos = self.taint_manager.get_taint_parameters(vuln_type, start_cpg_node, source_cpg_node, condition_node_dicts, index2)
                        self.log_manager.log_info(f'Obtain {len(taint_infos)} taint_infos!', False, 2)
                        for k in range(0, len(taint_infos)):
                            if find_poc:
                                break
                            index3 = index2 + f"[{str(k)}]"
                            self.log_manager.log_info(f'Processing Taint Info{index3}!', False, 3)
                            taint_info = taint_infos[k]
                            tainted_parameters = taint_info["Tainted_Parameters"]
                            vuln_codes = taint_info["Vuln_Codes"]
                            core_codes = taint_info["Core_Codes"]
                            interest_codes = taint_info["Interest_Codes"]
                            redirect_urls = taint_info["Redirect_URLs"]
                            conditions = taint_info["Conditions"]
                            user_input = taint_info["User_Input"]
                            db_operation = taint_info["DB_Operation"]
                            if interest_codes == []:
                                sink_nodes = list()
                                if db_operation["hava_write"] and vuln_type == "xss":
                                    payload = "<script>alert(2)</script>"
                                    payload = urllib.parse.quote(payload) # 进行URL编码
                                    cur_vuln_info = copy.deepcopy(vuln_info)
                                    cur_vuln_info["data"][vuln_parameter] = payload
                                    data = copy.deepcopy(cur_vuln_info["data"])
                                    self.merge_structure(user_input, data)
                                    poc = {"method": cur_vuln_info["method"], "path": cur_vuln_info["target_url"], "host": cur_vuln_info["base_url"]}
                                    for item in user_input.keys():
                                        if item not in poc.keys():
                                            poc[item] = user_input[item]
                                    automated_poc_list.append(poc)
                                    find_poc = True
                                    break
                                    # TODO: 这里暂时就这样处理
                                    # sink_nodes = self.taint_manager.process_read2sink(vuln_type, tainted_parameters, redirect_urls, db_operation)
                                else:
                                    sink_nodes = self.source_sink_handler.infer_sink_nodes(vuln_type, tainted_parameters, redirect_urls, index3)
                                for sink_node in sink_nodes:
                                    sink_code = sink_node["code"]
                                    code_path = sink_node["path"]
                                    if code_path:
                                        vuln_codes.append(f"\n\nHere is the code in the {code_path}:\n")
                                        vuln_codes.append(sink_code)
                                        core_codes.append(sink_code)
                                        interest_codes.append(sink_code)
                            if interest_codes == []:
                                self.log_manager.log_info(f'Discard Taint Info{index3}(can not find appropriate sink node)!', False, 3)
                                continue
                            self.log_manager.log_codes(vuln_codes, core_codes, interest_codes)
                            payload = self.taint_manager.infer_payload(vuln_type, vuln_parameter, interest_codes, index3)
                            payload = urllib.parse.quote(payload) # 进行URL编码
                            cur_vuln_info = copy.deepcopy(vuln_info)
                            cur_vuln_info["data"][vuln_parameter] = payload
                            data = copy.deepcopy(cur_vuln_info["data"])
                            self.merge_structure(user_input, data)
                            poc = {"method": cur_vuln_info["method"], "path": cur_vuln_info["target_url"], "host": cur_vuln_info["base_url"]}
                            for item in user_input.keys():
                                if item not in poc.keys():
                                    poc[item] = user_input[item]
                            automated_poc_list.append(poc)
                            find_poc = True
                            break
            self.joern_server.log_level = 2
        self.joern_server.close_cpg()
        # 构造最简单的poc
        if automated_poc_list == []:
            for i in range(0, len(vuln_infos)):
                vuln_info = vuln_infos[i]
                if vuln_info["vuln_parameters"] != []:
                    poc = {"method": vuln_info["method"], "path": vuln_info["target_url"], "host": vuln_info["base_url"], "data": vuln_info["data"]}
                    if poc["method"] is None:
                        poc["method"] = "POST"
                    if poc["path"] is None:
                        poc["path"] = "/"
                    if poc["host"] is None:
                        poc["host"] = "localhost"
                    automated_poc_list.append(poc)
        self.log_manager.log_result("automated_poc", automated_poc_list)
        return automated_poc_list