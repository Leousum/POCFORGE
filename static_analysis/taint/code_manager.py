import os
import sys
import json
import copy
static_analysis_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
autopoc_path = os.path.abspath(os.path.join(static_analysis_path, ".."))
sys.path.append(autopoc_path)
sys.path.append(static_analysis_path)
from utils.log_manager import LogManager
from joern_manager.joern import JoernServer
from pfg.pointer_flow_graph import PFGNode

class CodeManager():
    def __init__(self, joern_server: JoernServer, log_manager: LogManager) -> None:
        self.joern_server = joern_server
        self.log_manager = log_manager
        self.delete_line_map = dict() # 被删除的行号(key是filename,value是被删除的行号列表)
        self.interest_operations = dict()
        self.interest_operations_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "interest_operations.json")
        with open(self.interest_operations_path, "r", encoding = "utf-8") as f:
            self.interest_operations = json.load(f)

# ======================================== Collect Interest Code Start ========================================
    def _record_interest_operation(self, operator: str, operand1: PFGNode, operand2: PFGNode):
        # 记录含有污点变量的字符串拼接操作中的潜在漏洞字符串(未来可能会舍弃)
        vuln_type = self.log_manager.vuln_type
        vuln_key = vuln_type.replace(" ", "_")
        if vuln_key not in self.interest_operations.keys():
            self.interest_operations[vuln_key] = list()
        operation = dict()
        operation["operator"] = operator
        operation["operands"] = list()
        for operand in [operand1, operand2]:
            operation["operands"].append(operand.value)
        self.interest_operations[vuln_key].append(operation)
        with open(self.interest_operations_path, "w", encoding = "utf-8") as f:
            json.dump(self.interest_operations, f, ensure_ascii = False, indent = 4)
# ======================================== Collect Interest Code Start ========================================

# ======================================== Collect Related Code Start ========================================
    def get_filepath_by_id(self, cpg_id: str):
        # 获取CPG ID所处的文件路径
        filepath = self.joern_server.repo_path
        if cpg_id is not None:
            call_cpg_node = self.joern_server.find_cpg_call_node_location_by_id(cpg_id)
            if call_cpg_node is not None:
                for k in call_cpg_node.keys():
                    filename = k
                    if filename is not None and filename not in ["", "N/A"]:
                        filepath = os.path.join(self.joern_server.repo_path, filename)
        if filepath.find(".") != -1:
            return filepath
        return None
    
    def get_filepath(self, call_stmt):
        # 获取函数调用语句所处的文件路径
        filepath = self.joern_server.repo_path
        if call_stmt is not None:
            if call_stmt.cpg_id:
                call_cpg_node = self.joern_server.find_cpg_call_node_location_by_id(call_stmt.cpg_id)
                if call_cpg_node is not None:
                    for k in call_cpg_node.keys():
                        filename = k
                        if filename is not None and filename not in ["", "N/A"]:
                            filepath = os.path.join(self.joern_server.repo_path, filename)
        if filepath.find(".") != -1:
            return filepath
        return None
    
    def record_delete_line(self, cpg_node: dict):
        # 将要删除的代码行号记录在self.delete_line_map中
        line_numbers = list()
        source_file_path = None
        call_cpg_node = self.joern_server.find_cpg_call_node_location(cpg_node)
        if call_cpg_node is not None:
            for k in call_cpg_node.keys():
                source_filename = k
                source_lineNumber = int(call_cpg_node[k])
                line_numbers.append(source_lineNumber)
                if source_filename is not None and source_filename not in ["", "N/A"]:
                    source_file_path = os.path.join(self.joern_server.repo_path, source_filename)
                else:
                    source_file_path = self.joern_server.repo_path
                break
        # 获取source_node的所有后继节点的行号
        if source_file_path is not None:
            line_numbers.extend(self.get_dominates_lineNumbers(cpg_node))
            if source_file_path not in self.delete_line_map.keys():
                self.delete_line_map[source_file_path] = list()
            for line_number in line_numbers:
                if line_number not in self.delete_line_map[source_file_path]:
                    self.delete_line_map[source_file_path].append(line_number)
    
    def get_file_code(self, file_path: str, line_numbers: list, clean_space = True):
        # 根据文件绝对路径、行号收集所有需要的代码
        delete_line_numbers = list()
        if file_path is None:
            return []
        if file_path in self.delete_line_map.keys():
            delete_line_numbers = self.delete_line_map[file_path]
        line_numbers = list(set(line_numbers))
        line_numbers = sorted(line_numbers)
        min_index = line_numbers[0]
        max_index = line_numbers[-1]
        for i in range(min_index, max_index + 1):
            if i not in line_numbers:
                line_numbers.append(i)
        line_numbers = sorted(line_numbers)
        need_codes = list()
        codes = list()
        if os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    codes = f.read().decode('utf8','ignore').split("\n")
            except:
                pass
        for i in line_numbers:
            if i <= len(codes) and i >= 1 and i not in delete_line_numbers:
                if clean_space:
                    if codes[i - 1].replace("\t", "").replace("\n", ""):
                        need_codes.append(codes[i - 1])
                else:
                    need_codes.append(codes[i - 1]) 
        if len(need_codes) >= 2:
            if (need_codes[0].find("{") != -1 or need_codes[1].find("{") != -1) and need_codes[-1].find("}") == -1:
                prefix = ""
                for space in need_codes[0]:
                    if space == " ":
                        prefix += " "
                    else:
                        break
                need_codes.append(prefix + "}\n")
            left_brace_pos = need_codes[-1].rfind("{")
            right_brace_pos = need_codes[-1].rfind("}")
            if left_brace_pos != -1:
                if left_brace_pos > right_brace_pos:
                    prefix = ""
                    for space in need_codes[-1]:
                        if space == " ":
                            prefix += " "
                        else:
                            break
                    need_codes.append(prefix + "}\n")
        return need_codes

    def get_dominates_lineNumbers(self, cpg_node: dict):
        line_numbers = list()
        dominate_nodes = self.joern_server.find_dominate_nodes("call", cpg_node)
        for dominate_node in dominate_nodes:
            if isinstance(dominate_node, dict):
                if "lineNumber" in dominate_node.keys():
                    line_numbers.append(int(dominate_node["lineNumber"]))
        return line_numbers

    def collect_vuln_codes(self, source_cpg_node: dict, accessed_functions: list):
        # 收集所有相关代码
        self.log_manager.log_info(f'Collect Vulnerable Codes...', False, 3)
        vuln_codes = list()
        # 首先获取所有相关函数的代码
        filepath_method_map = dict()
        for method_full_name in accessed_functions:
            method_cpg_node = self.joern_server.find_method_by_fullname(method_full_name)
            if isinstance(method_cpg_node, dict):
                start = 0;end = 0;file_path = None
                if "filename" in method_cpg_node.keys():
                    if method_cpg_node["filename"] is not None and method_cpg_node["filename"] not in ["", "N/A", "empty", "<empty>"]:
                        file_path = os.path.join(self.joern_server.repo_path, method_cpg_node["filename"])
                    else:
                        file_path = self.joern_server.repo_path
                if file_path:
                    if "lineNumber" in method_cpg_node.keys():
                        start = int(method_cpg_node["lineNumber"])
                        end = start
                    if "lineNumberEnd" in method_cpg_node.keys():
                        end = int(method_cpg_node["lineNumberEnd"])
                    else:
                        dominate_nodes = self.joern_server.find_dominate_nodes("method", method_cpg_node)
                        for dominate_node in dominate_nodes[::-1]:
                            if "lineNumber" in dominate_node.keys():
                                end = int(dominate_node["lineNumber"])
                                break
                    if file_path not in filepath_method_map.keys():
                        filepath_method_map[file_path] = dict()
                    if method_full_name not in filepath_method_map[file_path].keys():
                        filepath_method_map[file_path][method_full_name] = list()
                        for line_num in range(start, end + 2):
                            filepath_method_map[file_path][method_full_name].append(line_num)
        for file_path in filepath_method_map.keys():
            vuln_codes.append(f'\n\nHere are the functions accessed in the "{file_path}":\n')
            for method_full_name in filepath_method_map[file_path].keys():
                vuln_codes.extend(self.get_file_code(file_path, filepath_method_map[file_path][method_full_name]))
                vuln_codes.append("\n")
        # 获取source_node的文件名、行号
        line_numbers = list()
        source_file_path = None
        call_cpg_node = self.joern_server.find_cpg_call_node_location(source_cpg_node)
        if call_cpg_node is not None:
            for k in call_cpg_node.keys():
                source_filename = k
                source_lineNumber = int(call_cpg_node[k])
                line_numbers.append(source_lineNumber)
                if source_filename is not None and source_filename not in ["", "N/A"]:
                    source_file_path = os.path.join(self.joern_server.repo_path, source_filename)
                else:
                    source_file_path = self.joern_server.repo_path
                break
        # 获取source_node的所有后继节点的行号
        if source_file_path is not None:
            vuln_codes.append(f"\n\nHere is the code in the {source_file_path}:\n")
            line_numbers.extend(self.get_dominates_lineNumbers(source_cpg_node))
            vuln_codes.extend(self.get_file_code(source_file_path, line_numbers))
        return vuln_codes
    
    def collect_core_codes(self, vuln_codes: list, tainted_parameters: list):
        # 收集核心代码(和污点变量有关的代码)
        core_codes = list()
        func_pos = list()
        func_start = 0
        func_end = 0
        source_start = 0
        for i in range(0, len(vuln_codes)):
            code = vuln_codes[i]
            if code.find("Here are the functions accessed in the") != -1:
                for j in range(i + 1, len(vuln_codes)):
                    if vuln_codes[j].find("Here are the functions accessed in the") != -1 or vuln_codes[j].find("Here is the code in the") != -1:
                        func_start = i
                        func_end = j - 1
                        break
                func_pos.append([func_start, func_end])
            elif code.find("Here is the code in the") != -1 and source_start == 0:
                source_start = i
        for pos in func_pos:
            flag = False
            start = pos[0]
            end = pos[1]
            for k in range(start, end + 1):
                code = vuln_codes[k]
                if flag:
                    break
                for tainted_parameter in tainted_parameters:
                    if code.find(tainted_parameter) != -1 or code.find(tainted_parameter.replace('"', "'").replace('\"', "\'")) != -1:
                        flag = True
                        break
            if flag:
                for k in range(start, end + 1):
                    code = vuln_codes[k]
                    if code:
                        core_codes.append(code)
        core_codes.append(f"\n{vuln_codes[source_start]}\n")
        for i in range(source_start, len(vuln_codes)):
            code = vuln_codes[i]
            flag = False
            for tainted_parameter in tainted_parameters:
                if code.find(tainted_parameter) != -1 or code.find(tainted_parameter.replace('"', "'").replace('\"', "\'")) != -1:
                    flag = True
                    break
            if flag:
                core_codes.append(code)
        return core_codes

    def collect_interest_codes(self, interest_flag: bool, interest_codes: list, cpg_node: dict):
        flag = False
        if interest_flag:
            top_parent_node = self.joern_server.find_astParent_until_top(cpg_node)
            if isinstance(top_parent_node, dict):
                if "code" in top_parent_node.keys():
                    if top_parent_node["code"] not in interest_codes:
                        interest_codes.append(top_parent_node["code"])
                        flag = True
        return flag
    
    def reduced_path(self, origin_path: str):
        # 简化路径
        final_path = None
        if origin_path and isinstance(origin_path, str):
            start = origin_path[:origin_path.find("=>")]
            end = origin_path[origin_path.rfind("=>") + len("=>"):]
            if start and end:
                if start != end:
                    final_path = start + "=>" + end
                else:
                    final_path = start
        if final_path == "=>":
            final_path = None
        return final_path

    def collect_report_codes(self, old_call_info: dict):
        # 收集报告所需的代码
        call_info = dict()
        call_info["path"] = self.reduced_path(old_call_info["path"])
        call_info["taint_data"] = old_call_info["taint_data"]
        call_info["call_stack"] = list()
        for old_item in old_call_info["call_stack"]:
            item = copy.deepcopy(old_item)
            if isinstance(item, dict):
                item["file_path"] = None
                item["prev_line"] = None
                item["start_line"] = None
                item["end_line"] = None
                item["next_line"] = None
                item["codes"] = list()
                file_path = None
                if isinstance(item["method_node"], dict):
                    if "lineNumber" in item["method_node"].keys():
                        item["prev_line"] = int(item["method_node"]["lineNumber"])
                    if "lineNumberEnd" in item["method_node"].keys():
                        item["next_line"] = int(item["method_node"]["lineNumberEnd"])
                if isinstance(item["call_node"], dict):
                    _, call_abs_path, call_line_num = self.joern_server.find_path_line(item["call_node"])
                    file_path = call_abs_path
                    item["file_path"] = f"In {call_abs_path}"
                    if isinstance(item["method_node"], dict) and "name" in item["method_node"].keys():
                        item["file_path"] += f', Function {item["method_node"]["name"]}()'
                    item["file_path"] += f', Line {str(call_line_num)}'
                    if "code" in item["call_node"].keys():
                        if item["call_node"]["code"] is not None:
                            item["file_path"] += f', {item["call_node"]["code"]}'
                    item["start_line"] = call_line_num
                    item["end_line"] = call_line_num # TODO: 调用点可能有多行,未来再改进
                    if item["next_line"] is None and call_line_num is not None:
                        item["next_line"] = call_line_num + 5
                if isinstance(item["first_node"], dict):
                    _, _, first_line_num = self.joern_server.find_path_line(item["first_node"])
                    item["prev_line"] = first_line_num
                if item["prev_line"] is not None and item["next_line"] is not None and item["file_path"] is not None:
                    item["codes"] = self.get_file_code(file_path, [item["prev_line"], item["next_line"]], False)
                if item["codes"] != [] and item["prev_line"] is not None:
                    if item["next_line"] > len(item["codes"]):
                        item["next_line"] = len(item["codes"]) + item["prev_line"]
                del item["call_node"]
                del item["first_node"]
                del item["method_node"]
                call_info["call_stack"].append(item)
        return call_info
# ======================================== Collect Related Code End ========================================