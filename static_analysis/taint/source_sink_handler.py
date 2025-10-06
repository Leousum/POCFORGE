import os
import json
import copy
import sys
static_analysis_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
autopoc_path = os.path.abspath(os.path.join(static_analysis_path, ".."))
sys.path.append(autopoc_path)
sys.path.append(static_analysis_path)
from joern_manager.stmt.stmt_data import Operation
from utils.log_manager import LogManager
from LLM.model_manager import ModelManager
from joern_manager.joern import JoernServer
from static_analysis.taint.code_manager import CodeManager

class SourceSinkHandler():
    def __init__(self, joern_server: JoernServer, model_manager: ModelManager, log_manager: LogManager) -> None:
        self.joern_server = joern_server
        self.log_manager = log_manager
        self.model_manager = model_manager
        self.code_manager = CodeManager(joern_server, log_manager)
        self.taint_config_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "taint_config.json")
        self.parameter_map_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "parameter_map.json")
        self.taint_config = None
        self.parameter_map = dict()
        with open(self.taint_config_path, "r", encoding = "utf-8") as f:
            self.taint_config = json.load(f)
        with open(self.parameter_map_path, "r", encoding = "utf-8") as f:
            self.parameter_map = json.load(f)
        self.prefixs = [letter for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
        self.prefix_map = dict()
        for i in range(len(self.prefixs)):
            self.prefix_map[self.prefixs[i]] = i
        if not os.path.exists(self.joern_server.vuln_feature_path):
            os.makedirs(self.joern_server.vuln_feature_path, mode = 0o777)
        self.cast_chars = ["int","integer","float","double","real","bool","boolean"]
        self.sanitizer_funcs = ["intval","floatval","doubleval","boolval","strpos","isset","global","count","preg_replace","preg_match","preg_match_all","preg_split","settyple","empty","unset","array"]

    # ======================================== Infer Source Nodes Start ========================================

    def make_choices(self, options: list, full_statements = []):
        num = -1
        choices = ""
        for prefix, item in zip(self.prefixs, options):
            num += 1
            if isinstance(item, str):
                choices += f"{prefix}.{item} \n"
            elif isinstance(item, dict):
                if full_statements:
                    choices += f'{prefix}."ID": {item["id"]}, "Code": {item["code"]}, "Full Statement": {full_statements[num]} \n'
                else:
                    choices += f'{prefix}."ID": {item["id"]}, "Code": {item["code"]}, "Full Statement": "not get" \n'
        return choices

    def fliter_source_nodes(self, cpg_nodes: list):
        # TODO:这里如何确定source节点还需要改进
        source_cpg_nodes = list()
        for cpg_node in cpg_nodes:
            if isinstance(cpg_node, dict):
                if "methodFullName" in cpg_node.keys() and cpg_node["methodFullName"].find("<operator>.assignment") == -1:
                    if cpg_node["methodFullName"].find("<operator>") != -1:
                        if cpg_node["methodFullName"] == "<operator>.indexAccess":
                            source_cpg_nodes.append(cpg_node)
                    else:
                        source_cpg_nodes.append(cpg_node)
        return source_cpg_nodes

    def sort_cpg_nodes(self, cpg_nodes: list, file_relative_path: str, index):
        # 对CPG Nodes进行排序
        # (1) 获取所有节点的文件名称
        file_names = list()
        file_row_map = dict()
        for cpg_node in cpg_nodes:
            if isinstance(cpg_node, dict):
                if cpg_node["filename"]:
                    file_names.append(cpg_node["filename"])
                else:
                    file_names.append("None")
        file_names = list(set(file_names))
        file_names = sorted(list(set(file_names)))
        # (2) 获取所有节点的所处行数并对其排序
        for file_name in file_names:
            file_row_map[file_name] = list()
            for cpg_node in cpg_nodes:
                if isinstance(cpg_node, dict):
                    if cpg_node["filename"]:
                        if cpg_node["filename"] == file_name:
                            file_row_map[file_name].append(cpg_node["lineNumber"])
                    else:
                        file_row_map["None"].append(cpg_node["lineNumber"])
            file_row_map[file_name] = list(set(file_row_map[file_name]))
            file_row_map[file_name] = sorted(file_row_map[file_name])
        # (3) 按照已经排序好了的文件名称+行数对cpg_nodes进行第一轮排序(根据file_relative_path)
        temp_candidate_cpg_nodes1 = list()
        if file_relative_path:
            if file_relative_path in file_row_map.keys():
                for row_num in file_row_map[file_relative_path]:
                    for cpg_node in cpg_nodes:
                        if isinstance(cpg_node, dict):
                            if cpg_node["filename"] == file_relative_path and cpg_node["lineNumber"] == row_num:
                                temp_candidate_cpg_nodes1.append(cpg_node)
        else:
            for file_name in file_row_map.keys():
                for row_num in file_row_map[file_name]:
                    for cpg_node in cpg_nodes:
                        if isinstance(cpg_node, dict):
                            if cpg_node["filename"]:
                                if cpg_node["filename"] == file_name and cpg_node["lineNumber"] == row_num:
                                    temp_candidate_cpg_nodes1.append(cpg_node)
                            else:
                                if file_name == "None" and cpg_node["lineNumber"] == row_num:
                                    temp_candidate_cpg_nodes1.append(cpg_node)
        # (4) 根据文件名称、代码和行号删除一部分的候选节点(相当于去重)
        temp_candidate_cpg_nodes2 = list()
        file_row_code_list = list()
        for cpg_node in temp_candidate_cpg_nodes1:
            if isinstance(cpg_node, dict):
                if cpg_node["filename"]:
                    file_row_code = f'{cpg_node["filename"]} {str(cpg_node["lineNumber"])} {cpg_node["code"]}'
                    if file_row_code not in file_row_code_list:
                        file_row_code_list.append(file_row_code)
                        temp_candidate_cpg_nodes2.append(cpg_node)
                else:
                    temp_candidate_cpg_nodes2.append(cpg_node)
        # (5) 根据所处的完整语句来做进一步筛选(删除控制结构语句)
        full_statements = list()
        candidate_cpg_nodes = list()
        for cpg_node in temp_candidate_cpg_nodes2:
            cpg_node["_label"] = "CALL"
            parent_node = self.joern_server.find_astParent_until_top(cpg_node)
            if isinstance(parent_node, dict):
                if parent_node["_label"] != "CONTROL_STRUCTURE":
                    candidate_cpg_nodes.append(cpg_node)
                    full_statements.append(parent_node["code"])
            else:
                candidate_cpg_nodes.append(cpg_node)
                full_statements.append("None")
        # (6) 记录并返回结果
        items = list()
        if full_statements:
            for cpg_node, full_statement in zip(candidate_cpg_nodes, full_statements):
                item = dict()
                item["cpg_node"] = cpg_node
                item["full_statement"] = full_statement
                items.append(item)
        else:
            for cpg_node in candidate_cpg_nodes:
                item = dict()
                item["cpg_node"] = cpg_node
                items.append(item)
        self.log_manager.log_result(f"candidate_cpg_nodes{index}", items)
        return candidate_cpg_nodes, full_statements
    
    def infer_start_cpg_node(self, file_relative_path: str, source_cpg_node: dict):
        # 推断起始分析节点
        start_cpg_node = None
        condition_node_dicts = list()
        # (1) 迭代查找source node最终的调用点
        top_call_site = self.joern_server.find_top_call_site(file_relative_path, source_cpg_node)
        if top_call_site:
            if isinstance(top_call_site, dict):
                if "id" in top_call_site.keys():
                    start_cpg_node = self.joern_server.find_cpg_node_by_id(top_call_site["id"])
        # (2) 找到所属控制结构,并确定所属分支(True/False),以分支的第1行作为起始分析点
        source_fullstmt_node = None
        if start_cpg_node is None:
            control_nodes = self.joern_server.find_controlledBy_nodes(source_cpg_node)
            nearest_call_node = None
            if control_nodes:
                source_fullstmt_node = self.joern_server.find_astParent_until_top(source_cpg_node)
                for control_node in control_nodes:
                    if isinstance(control_node, dict):
                        control_structure_node = self.joern_server.find_astParent_until_top(control_node)
                        if control_structure_node["_label"] == "CONTROL_STRUCTURE":
                            # 检查各个分支是否含有source node
                            keep_call_node = None
                            cfg_out_call_nodes = self.joern_server.find_cfgOut_until_call(control_node, True)
                            if control_structure_node["controlStructureType"] == "IF":
                                if len(cfg_out_call_nodes) >= 1:
                                    if self.joern_server.check_dominate_node(cfg_out_call_nodes[0], source_fullstmt_node):
                                        keep_call_node = cfg_out_call_nodes[0]
                                        condition_node_dicts.append({"condition_node": control_node, "operation_result": True})
                                    else:
                                        if len(cfg_out_call_nodes) > 1:
                                            keep_call_node = cfg_out_call_nodes[1]
                                        condition_node_dicts.append({"condition_node": control_node, "operation_result": False})
                            elif control_structure_node["controlStructureType"] == "SWITCH":
                                case_nodes = self.joern_server.find_switch_case(control_node)
                                if len(case_nodes) == len(cfg_out_call_nodes):
                                    for case_node, cfg_out_call_node in zip(case_nodes, cfg_out_call_nodes):
                                        if self.joern_server.check_dominate_node(cfg_out_call_node, source_fullstmt_node):
                                            keep_call_node = cfg_out_call_node
                                            if "name" in case_node.keys() and "code" in case_node.keys():
                                                if case_node["name"] != "default" and case_node["code"] != "default":
                                                    new_stmt = Operation()
                                                    condition_stmt = self.joern_server.parse_stmt(control_node)
                                                    case_stmt = self.joern_server.parse_stmt(case_node)
                                                    new_stmt.operator = "<operator>.equals"
                                                    new_stmt.code = f"{condition_stmt.code} == {case_stmt.code}"
                                                    new_stmt.operands.append(condition_stmt)
                                                    new_stmt.operands.append(case_stmt)
                                                    condition_node_dicts.append({"condition_stmt": new_stmt, "operation_result": True})
                            # 更新最靠近source node的节点nearest node
                            if keep_call_node is not None:
                                if nearest_call_node is None:
                                    nearest_call_node = keep_call_node
                                else:
                                    if abs(int(nearest_call_node["id"]) - int(source_cpg_node["id"])) > abs(int(keep_call_node["id"]) - int(source_cpg_node["id"])):
                                        nearest_call_node = keep_call_node
            if nearest_call_node is not None:
                start_cpg_node = self.joern_server.find_astParent_until_top(nearest_call_node)
        # (3) 未找到任何调用点时以source node所在语句为起始分析节点
        if start_cpg_node is None:
            if source_fullstmt_node is not None:
                start_cpg_node = source_fullstmt_node
            else:
                start_cpg_node = self.joern_server.find_astParent_until_top(source_cpg_node)
        return start_cpg_node, condition_node_dicts

    def infer_source_cpg_node(self, vuln_type: str, vuln_parameter: str, file_relative_path: str, index: int):
        # 根据参数名称和文件名称推断出多个source node、start node、condition node字典
        infos = list()
        # (0) 读取已经推断出了的信息
        if self.log_manager.get_log_result(f"choose_cpg_nodes{index}"):
            return self.log_manager.get_log_result(f"choose_cpg_nodes{index}")
        # (1) 构造真正的参数(这里是为了处理HTTP请求中的header,cookie两项参数转换)
        temp_vuln_parameter = vuln_parameter
        if vuln_parameter is not None:
            if vuln_parameter.lower() in self.parameter_map.keys():
                temp_vuln_parameter = self.parameter_map[vuln_parameter.lower()]
        # (2) 以参数名称+文件名称为关键字搜索节点
        candidate_cpg_nodes = list()
        if temp_vuln_parameter is not None and file_relative_path is not None:
            candidate_cpg_nodes = self.joern_server.find_cfg_node_by_contain(
                parameter = f'\\"{temp_vuln_parameter}\\"',
                relative_path = file_relative_path
            )
            candidate_cpg_nodes = self.fliter_source_nodes(candidate_cpg_nodes)
        if candidate_cpg_nodes == []:
            candidate_cpg_nodes = self.joern_server.find_cfg_node_by_contain(
                parameter = f'{temp_vuln_parameter}',
                relative_path = file_relative_path
            )
            candidate_cpg_nodes = self.fliter_source_nodes(candidate_cpg_nodes)
        # (3) 找到所有用户可输入且参数固定的节点
        if candidate_cpg_nodes == []:
            candidate_cpg_nodes = self.joern_server.find_user_input_nodes(
                php_global_vars = self.taint_config["sources"]["php_global_vars"],
                vuln_parameter = temp_vuln_parameter
            )
            candidate_cpg_nodes = self.fliter_source_nodes(candidate_cpg_nodes)
        # (4) 找到所有用户可输入的节点
        if candidate_cpg_nodes == []:
            candidate_cpg_nodes = self.joern_server.find_user_input_nodes(
                php_global_vars = self.taint_config["sources"]["php_global_vars"],
                vuln_parameter = None
            )
            candidate_cpg_nodes = self.fliter_source_nodes(candidate_cpg_nodes)
        # (5) 节点排序,获取完整语句
        candidate_cpg_nodes, full_statements = self.sort_cpg_nodes(candidate_cpg_nodes, file_relative_path, index)
        # (6) 使用LLM挑选出合适的source cpg node
        choices = self.make_choices(candidate_cpg_nodes, full_statements)
        if choices:
            answer = None
            if len(choices) == 1:
                answer = "A"
            elif len(choices) > 1:
                answer = self.model_manager.choose_source_node(vuln_type, vuln_parameter, choices)
            if answer:
                options = answer.strip("<").strip(">").replace(" ", "").split(",")
                for option in options:
                    if option:
                        option_res = option[0].upper()
                        if option_res in self.prefix_map.keys():
                            source_cpg_node = candidate_cpg_nodes[self.prefix_map[option_res]]
                            # (7) 找到起始分析位置
                            if source_cpg_node is not None:
                                source_cpg_node = self.joern_server.find_cpg_node_by_id(source_cpg_node["id"])
                                start_cpg_node, condition_node_dicts = self.infer_start_cpg_node(file_relative_path, source_cpg_node)
                                if start_cpg_node is not None:
                                    info = dict()
                                    info["start_cpg_node"] = start_cpg_node
                                    info["source_cpg_node"] = source_cpg_node
                                    info["condition_node_dicts"] = condition_node_dicts
                                    infos.append(info)
        self.log_manager.log_result(f"choose_cpg_nodes{index}", infos)
        return infos
    
# ======================================== Infer Source Nodes End ========================================

# ======================================== Infer Sink Nodes Start ========================================
    def collect_sink_short_names(self, vuln_type):
        # 收集sink函数的名称
        sink_short_names = list()
        for short_name in self.taint_config["sinks"].keys():
            func = self.taint_config["sinks"][short_name]
            if func["vuln_type"] == vuln_type:
                sink_short_names.append(short_name)
        return sink_short_names

    def collect_sink_codes(self, possible_sink_nodes: list):
        # 收集sink点的代码
        code_path_map = dict()
        processed_sinks = list()
        for node in possible_sink_nodes:
            if isinstance(node, dict) and "filename" in node.keys() and "lineNumber" in node.keys():
                file_path = "None"
                if node["filename"] is not None and node["filename"] not in ["", "N/A", "empty", "<empty>"]:
                    file_path = os.path.join(self.joern_server.repo_path, node["filename"])
                else:
                    file_path = self.joern_server.repo_path
                if os.path.exists(file_path):
                    file_row = file_path + "_" + str(node["lineNumber"])
                    if file_row not in processed_sinks:
                        processed_sinks.append(file_row)
                        line_numbers = [int(node["lineNumber"])]
                        sink_code = self.code_manager.get_file_code(file_path, line_numbers)
                        sink_code = "".join(sink_code)
                        if sink_code not in code_path_map.keys():
                            code_path_map[sink_code] = list()
                        if file_path not in code_path_map[sink_code]:
                            code_path_map[sink_code].append(file_path)
        return code_path_map

    def infer_sink_nodes(self, vuln_type, taint_parameters: list, redirect_urls: list, index: int):
        # 根据污点变量和文件名称推断出1个sink点
        sink_nodes = list()
        if self.log_manager.get_log_result(f"sink_nodes{index}"):
            return self.log_manager.get_log_result(f"sink_nodes{index}")
        self.joern_server.log_level = 4
        for taint_parameter in taint_parameters:
            self.log_manager.log_info(f'Process Tainted Parameters: {taint_parameter}', False, 3)
            sink_short_names = self.collect_sink_short_names(vuln_type)
            possible_sink_nodes = self.joern_server.find_possible_sink_nodes(sink_short_names, taint_parameter, redirect_urls)
            candidate_code_path_map = self.collect_sink_codes(possible_sink_nodes)
            # candidate_code_path_map = self.page_manager.infer_sinks(self.joern_server.repo_path, taint_parameter, redirect_url)
            choices = self.make_choices(list(candidate_code_path_map.keys()))
            if choices:
                answer = self.model_manager.choose_sink_node(vuln_type, taint_parameter, choices)
                if answer:
                    answer = answer[0].upper()
                    if answer in self.prefix_map.keys():
                        code = list(candidate_code_path_map.keys())[self.prefix_map[answer]]
                        path_list = candidate_code_path_map[code]
                        code_path = None
                        if path_list:
                            code_path = path_list[0]
                        sink_node = dict()
                        sink_node["code"] = code
                        sink_node["path"] = code_path
                        sink_nodes.append(sink_node)
                        self.joern_server.log_level = 3
        self.joern_server.log_level = 3
        self.log_manager.log_result(f"sink_nodes{index}", sink_nodes)
        return sink_nodes

# ======================================== Infer Sink Nodes End ========================================

# ======================================== (0-day Vulnerability) Infer Source Nodes Start ========================================
    def get_separate_sources(self):
        source_vars = list()
        source_funcs = list()
        # 读取公共source列表
        if "sources" in self.taint_config.keys():
            if "php_global_vars" in self.taint_config["sources"].keys():
                for var in self.taint_config["sources"]["php_global_vars"]:
                    source_vars.append(var)
        # 读取独有source列表
        feature_path = os.path.join(self.joern_server.vuln_feature_path, "feature.json")
        if os.path.exists(feature_path):
            feature_dict = dict()
            with open(feature_path, "r", encoding = "utf-8") as f:
                feature_dict = json.load(f)
            if "source" in feature_dict.keys():
                if "vars" in feature_dict["source"].keys():
                    for var in feature_dict["source"]["vars"]:
                        source_vars.append(var)
                if "funcs" in feature_dict["source"].keys():
                    for short_name in feature_dict["source"]["funcs"].keys():
                        source_funcs.append(short_name)
        return source_vars, source_funcs
    
    def get_sources(self):
        sources = list()
        source_vars, source_funcs = self.get_separate_sources()
        sources.extend(source_vars)
        sources.extend(source_funcs)
        sources = list(set(sources))
        return sources
    
    def filter_source(self, sources: list, cpg_node: dict):
        # 初步排除sanitizer:source不应该被处理
        if sources is None or sources == []:
            return True
        is_possible_source = True
        if isinstance(cpg_node, dict):
            if "code" in cpg_node.keys():
                code = cpg_node["code"]
                # 检查源代码中的未被清理的source数量
                source_num = 0
                for source in sources:
                    source_num += code.count(source)
                for special_char in self.cast_chars:
                    for source in sources:
                        sanitizer_chars = [f'({special_char})({source}', f'({special_char}) ({source}', f'({special_char}){source}', f'({special_char}) {source}']
                        for sanitizer_char in sanitizer_chars:
                            source_num -= code.count(sanitizer_char)
                for func_char in self.sanitizer_funcs:
                    for source in sources:
                        sanitizer_char = f"{func_char}({source}"
                        source_num -= code.count(sanitizer_char)
                if source_num <= 0:
                    is_possible_source = False
            else:
                is_possible_source = False
        else:
            is_possible_source = False
        return is_possible_source

    def get_entry_infos(self, cpg_node: dict):
        # 获取分析入口点
        visited = list()
        entry_ids = list()
        entry_infos = list()
        callsite_list = list()
        callsite_list.append((cpg_node, {"taint_data": None, "call_stack": []}))
        while callsite_list != []:
            temp_call_node, temp_call_info = callsite_list.pop()
            call_node = copy.deepcopy(temp_call_node)
            call_info = copy.deepcopy(temp_call_info)
            if isinstance(call_node, dict):
                if "id" in call_node.keys() and call_node["id"] not in visited:
                    visited.append(call_node["id"])
                    method_node = self.joern_server.find_belong_method(call_node)
                    if method_node is not None:
                        # 如果属于函数,就继续分析这个函数的调用点
                        call_sites = self.joern_server.find_call_sites(method_node)
                        item = dict()
                        item["call_node"] = copy.deepcopy(call_node)
                        item["method_node"] = copy.deepcopy(method_node)
                        item["first_node"] = None
                        call_info["call_stack"].insert(0, item)
                        for call_site in call_sites:
                            callsite_list.append((call_site, call_info))
                    else:
                        # 如果不属于函数,就找到所处文件第一条语句
                        first_node = self.joern_server.find_dominated_first_node(call_node)
                        if first_node is not None:
                            if isinstance(first_node, dict):
                                if "id" in first_node.keys() and first_node["id"] not in entry_ids:
                                    entry_ids.append(first_node["id"])
                                    entry_node = self.joern_server.find_astParent_until_top(first_node)
                                    item = dict()
                                    item["call_node"] = copy.deepcopy(call_node)
                                    item["first_node"] = copy.deepcopy(first_node)
                                    item["method_node"] = None
                                    call_info["call_stack"].insert(0, item)
                                    entry_infos.append({"entry_node": entry_node, "call_info": call_info})
                        else:
                            if call_node["id"] not in entry_ids:
                                entry_ids.append(call_node["id"])
                                entry_node = self.joern_server.find_astParent_until_top(call_node)
                                item = dict()
                                item["call_node"] = copy.deepcopy(call_node)
                                item["first_node"] = copy.deepcopy(call_node)
                                item["method_node"] = None
                                call_info["call_stack"].insert(0, item)
                                entry_infos.append({"entry_node": entry_node, "call_info": call_info})
        entry_infos = self.joern_server.remove_duplicate_nodes(entry_infos)
        return entry_infos

# ======================================== (0-day Vulnerability) Infer Source Nodes End ========================================

# ======================================== (0-day Vulnerability) Infer Sink Nodes Start ========================================

    def get_sinks(self):
        sinks = list()
        # 读取公共sink列表
        if "sinks" in self.taint_config.keys():
            sinks = list(self.taint_config["sinks"].keys())
        # 读取独有sink列表
        feature_path = os.path.join(self.joern_server.vuln_feature_path, "feature.json")
        if os.path.exists(feature_path):
            feature_dict = dict()
            with open(feature_path, "r", encoding = "utf-8") as f:
                feature_dict = json.load(f)
            if "sink" in feature_dict.keys():
                if "funcs" in feature_dict["sink"].keys():
                    for short_name in feature_dict["sink"]["funcs"].keys():
                        sinks.append(short_name)
        return sinks

# ======================================== (0-day Vulnerability) Infer Sink Nodes End ========================================

# ======================================== Get Redirect Start ========================================
    def get_redirects(self):
        # 获取跳转函数的函数名称列表
        redirects = list(self.taint_config["redirect"].keys())
        return redirects
# ======================================== Get Redirect End ========================================

if __name__ == "__main__":
    log_manager = LogManager(source_id="test", vuln_type = "test")
    config_path = os.path.join(os.path.abspath(os.path.join(os.path.join(os.path.dirname(__file__), ".."), "..")), "config.json")
    config_file = dict()
    with open(config_path, "r", encoding = "utf-8") as f:
        config_file = json.load(f)
    joern_server = JoernServer(
        config_file = config_file,
        repo_path = "/home/devdata/repos/cacti_cacti",
        log_manager = log_manager
    )
    model_manager = ModelManager(config_file, log_manager)
    s2_handler = SourceSinkHandler(joern_server, model_manager, log_manager)
    #s2_handler.get_source_nodes()
    s2_handler.get_sink_nodes()