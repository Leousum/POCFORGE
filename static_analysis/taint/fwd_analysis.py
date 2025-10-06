import os
import sys
import json
import copy
import shutil
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pfg.pointer_flow_graph import PointerFlowGraph
from static_analysis.taint.base_analysis import BaseAnalyzer

class ForwardAnalyzer(BaseAnalyzer):
    def __init__(self, config_file, joern_server, page_manager, model_manager, log_manager, s2_handler = None):
        super().__init__(config_file, joern_server, page_manager, model_manager, log_manager, s2_handler)
        # self.vuln_feature_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "vuln_feature", repo_path.strip("/").split("/")[-1])
        self.summary_root = os.path.join(config_file["summary_root"], joern_server.repo_path.strip("/").split("/")[-1])
        self.file_path = os.path.join(self.summary_root, "files")
        self.func_path = os.path.join(self.summary_root, "funcs")
        self.segment_path = os.path.join(self.summary_root, "segments")
        self.pfg_stmt_root = os.path.join(self.summary_root, "pfg_stmt_map")
        paths = [self.summary_root, self.file_path, self.func_path, self.segment_path, self.pfg_stmt_root]
        for summary_path in paths:
            if not os.path.exists(summary_path):
                os.makedirs(summary_path, mode = 0o777)
    
    def copy_map_info(self, PFG_in: PointerFlowGraph, index: int):
        # 复制存放数据流约束信息的文件夹
        if index == 0:
            return PFG_in
        else:
            num = 1
            PFG_out = copy.deepcopy(PFG_in)
            path_prefix = PFG_out.pfg_stmt_path.split("/")[-1]
            if path_prefix.rfind("_") != -1:
                path_prefix = path_prefix[:path_prefix.rfind("_")]
            PFG_out.pfg_stmt_path = os.path.join(self.pfg_stmt_root, f"{path_prefix}_{str(num)}")
            while os.path.exists(PFG_out.pfg_stmt_path):
                num += 1
                PFG_out.pfg_stmt_path = os.path.join(self.pfg_stmt_root, f"{path_prefix}_{str(num)}")
            if PFG_in.pfg_stmt_path != PFG_out.pfg_stmt_path:
                shutil.copytree(PFG_in.pfg_stmt_path, PFG_out.pfg_stmt_path)
            return PFG_out

    def init_summary(self, start_cpg_node: dict, call_stmt, PFG: PointerFlowGraph, analyze_all: bool, node_id: str):
        # 初始化摘要信息
        summary = dict()
        summary["start_cpg_id"] = start_cpg_node["id"]
        summary["start_file"] = self.code_manager.get_filepath_by_id(start_cpg_node["id"])
        summary["shortName"] = None
        summary["parameters"] = {}
        if call_stmt is not None and PFG is not None:
            if call_stmt.method is not None:
                summary["shortName"] = call_stmt.method.shortName
                for parameter_index in call_stmt.method.parameters.keys():
                    summary["parameters"][parameter_index] = PFG.stmt2json(call_stmt.method.parameters[parameter_index])
        summary_root = ""
        if summary["shortName"]:
            summary_root = os.path.join(self.func_path, summary["shortName"].replace(" ",""))
            if not analyze_all and node_id is not None:
                summary_root = os.path.join(self.func_path, summary["shortName"].replace(" ","") + "_to_" + str(node_id))
        else:
            summary_root = os.path.join(self.segment_path, str(summary["start_cpg_id"]))
            if not analyze_all and node_id is not None:
                summary_root = os.path.join(self.segment_path, str(summary["start_cpg_id"]) + "_to_" + str(node_id))
        if not os.path.exists(summary_root):
            os.makedirs(summary_root, mode = 0o777)
        summary_path = os.path.join(summary_root, "summary.json")
        # 为了避免重复分析递归函数,对每个函数都只会分析一遍
        if os.path.exists(summary_path):
            return summary_root, False
        else:
            with open(summary_path, "w", encoding = "utf-8") as f:
                json.dump(summary, f, ensure_ascii = False, indent = 4)
            return summary_root, True

    def map_func_return(self, PFG: PointerFlowGraph, stmt, return_stmt):
        # 构建函数返回值的映射关系
        if stmt is not None and return_stmt is not None:
            map_path = os.path.join(PFG.pfg_stmt_path, "-" + str(stmt.cpg_id) + ".json")
            map_data = dict()
            map_data["pfg_id"] = None
            map_data["stmt"] = stmt.to_json()
            map_data["stmt_str"] = PFG.json2str(map_data["stmt"])
            map_data["expression"] = return_stmt.to_json()
            map_data["expression_str"] = PFG.json2str(map_data["expression"])
            # 保存结果
            with open(map_path, "w", encoding = "utf-8") as f:
                json.dump(map_data, f, ensure_ascii = False, indent = 4)

    def merge_summary(self, code_block_id: str, stmt: any, summary_root: str, func_summary_root: str, PFG: PointerFlowGraph, accessed_functions: list, control_constraints: list, db_operation: dict, node_id: str):
        # 合并函数调用的摘要信息
        find_sink = False
        contexts = list()
        # 获取参数映射关系
        parameter_map = self.get_parameter_map(stmt, PFG)
        # 读取函数摘要
        for filename in os.listdir(func_summary_root):
            func_summary_path = os.path.join(func_summary_root, filename)
            if filename == "summary.json":
                continue
            func_summary = dict()
            with open(func_summary_path, "r", encoding = "utf-8") as f:
                func_summary = json.load(f)
            # 记录当前摘要信息
            info = dict()
            info["type"] = func_summary["type"]
            info["end_cpg_id"] = func_summary["end_cpg_id"]
            info["return_result"] = None
            info["sink"] = {}
            info["sink_code"] = None
            info["tainted_parameters"] = PFG.get_tainted_parameters()
            info["tainted_parameters"].extend(func_summary["tainted_parameters"])
            info["need_taint"] = []
            info["redirect"] = {}
            info["redirect_code"] = None
            info["redirect_file"] = None
            info["data_constraints"] = None
            info["control_constraints"] = []
            info["end_file"] = func_summary["end_file"]
            info["funcs"] = copy.deepcopy(accessed_functions)
            info["funcs"].extend(func_summary["funcs"])
            info["db_operation"] = None
            info["whole_path"] = PFG.get_visited_path() + "->" + func_summary["whole_path"]
            new_PFG = self.copy_map_info(copy.deepcopy(PFG), 1)
            new_accessed_functions = copy.deepcopy(accessed_functions)
            new_accessed_functions.extend(func_summary["funcs"])
            # 合并控制流约束信息(注意:控制流信息必须在数据流信息之前导入)
            new_control_constraints = copy.deepcopy(control_constraints)
            for control_constraint in func_summary["control_constraints"]:
                constraint = dict()
                constraint["condition_json"] = self.two_para2arg(control_constraint["condition_json"], parameter_map, new_PFG)
                constraint["operation_result"] = control_constraint["operation_result"]
                new_control_constraints.append(constraint)
            info["control_constraints"] = copy.deepcopy(new_control_constraints)
            # 合并数据库操作信息(TODO: 待检查)
            new_db_operation = copy.deepcopy(db_operation)
            new_db_operation["hava_write"] = (new_db_operation["hava_write"] or func_summary["db_operation"]["hava_write"])
            new_db_operation["cpg_ids"].extend(func_summary["db_operation"]["cpg_ids"])
            new_db_operation["db_triples"].extend(func_summary["db_operation"]["db_triples"])
            info["db_operation"] = copy.deepcopy(new_db_operation)
            # 记录返回值/sink/redirect函数信息(注意:应该在导入数据流约束之前执行,因为这部分信息也已经含有相应的数据流信息)
            if func_summary["type"] == "start2return":
                # (1) 处理函数返回
                if func_summary["return_result"] is not None:
                    return_json = self.two_para2arg(func_summary["return_result"], parameter_map, new_PFG)
                    return_stmt = self.joern_server.json2stmt(return_json)
                    new_PFG.call_return[stmt.cpg_id] = self.process_stmt_data(return_stmt, code_block_id, new_PFG, {"nodes": [], "field_edges": []}, add_node_flag = True)
                    self.map_func_return(new_PFG, stmt, return_stmt)
            elif func_summary["type"] == "start2sink":
                # (2) 处理sink函数
                info["sink"] = self.two_para2arg(func_summary["sink"], parameter_map, new_PFG)
                info["sink_code"] = new_PFG.json2str(info["sink"])
                info["need_taint"] = self.get_need_taint(info["sink"], new_PFG)
                if info["end_cpg_id"] is not None and node_id is not None:
                    if info["end_cpg_id"] == node_id:
                        find_sink = True
            elif func_summary["type"] == "start2redirect":
                # (3) 处理重定向函数
                info["redirect"] = self.two_para2arg(func_summary["redirect"], parameter_map, new_PFG)
                info["redirect_code"] = new_PFG.json2str(info["redirect_code"])
                info["redirect_file"] = func_summary["redirect_file"]
            # 合并数据流约束(通过执行语句来完成合并)
            if func_summary["type"] == "start2return":
                for constraint in func_summary["data_constraints"]:
                    if self.hava_parameter(constraint, parameter_map, True):
                        new_stmt = self.joern_server.json2stmt(self.two_para2arg(constraint, parameter_map, new_PFG))
                        new_PFG = self.analyze_stmt(new_stmt, new_PFG, code_block_id, False)
                contexts.append({"PFG":new_PFG,"funcs":new_accessed_functions,"cons":new_control_constraints,"db_op":new_db_operation})
            elif func_summary["type"] in ["start2sink", "start2redirect"]:
                for constraint in func_summary["data_constraints"]:
                    if self.hava_parameter(constraint, parameter_map, False):
                        new_stmt = self.joern_server.json2stmt(self.two_para2arg(constraint, parameter_map, new_PFG))
                        new_PFG = self.analyze_stmt(new_stmt, new_PFG, code_block_id, False)
                info["data_constraints"] = new_PFG.get_data_flow_constraints()
                # 保存信息
                if not (func_summary["type"] == "start2sink" and info["need_taint"] == []):
                    sub_summary_path = self.get_new_sub_summary_path(summary_root)
                    with open(sub_summary_path, "w", encoding = "utf-8") as f:
                        json.dump(info, f, ensure_ascii = False, indent = 4)
                shutil.rmtree(new_PFG.pfg_stmt_path) # TODO:思考这里需不需要删除掉 new_PFG.pfg_stmt_path 文件夹?
        return find_sink, contexts
    
    def get_need_taint(self, data: dict, PFG: PointerFlowGraph):
        variables = list()
        need_taint = list()
        self.extract_variables(data, variables)
        for variable in variables:
            variable_str = PFG.json2str(variable)
            if variable_str:
                need_taint.append(variable_str)
        temp_vars = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"]
        php_global_vars = ["_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_FILES", "_SESSION", "_ENV", "$GLOBALS"]
        global_vars = ["$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE", "$_FILES", "$_SESSION", "$_ENV", "$GLOBALS"]
        need_taint = list(set(need_taint) - set(temp_vars) - set(php_global_vars) - set(global_vars))
        return need_taint

    def extract_variables(self, data: dict, variables: list):
        # 判断一个变量具体由哪些变量组成
        if isinstance(data, dict):
            if "node_type" in data.keys():
                if self.is_var(data):
                    flag = True
                    for item in variables:
                        if item == data:
                            flag = False
                            break
                    if flag:
                        variables.append(copy.deepcopy(data))
                else:
                    for k in data.keys():
                        self.extract_variables(data[k], variables)
            else:
                for k in data.keys():
                    self.extract_variables(data[k], variables)
        elif isinstance(data, list):
            for info in data:
                self.extract_variables(info, variables)

    def get_new_sub_summary_path(self, summary_root: str):
        # 获取子摘要新的保存路径
        num = 1
        sub_summary_path = os.path.join(summary_root, f"summary_{str(num)}.json")
        while os.path.exists(sub_summary_path):
            num += 1
            sub_summary_path = os.path.join(summary_root, f"summary_{str(num)}.json")
        return sub_summary_path

    def record_summary(self, type: str, summary_root: str, end_node: dict, stmt: any, PFG: PointerFlowGraph, db_operation: dict, control_constraints: list, accessed_functions: list):
        # 记录摘要信息
        # 读取已有摘要
        if end_node is not None:
            if isinstance(end_node, dict):
                if "id" in end_node.keys():
                    summary_path = os.path.join(summary_root, "summary.json")
                    summary = dict()
                    with open(summary_path, "r", encoding = "utf-8") as f:
                        summary = json.load(f)
                    sub_summary_path = self.get_new_sub_summary_path(summary_root)
                    # 记录当前摘要信息
                    info = dict()
                    info["type"] = type
                    info["end_cpg_id"] = end_node["id"]
                    # 函数返回值信息(只有(a)call到return才需要记录此信息)
                    info["return_result"] = None
                    # sink相关信息(不必记录所有出现过的sink)
                    info["sink"] = {}
                    info["sink_code"] = None
                    info["tainted_parameters"] = PFG.get_tainted_parameters()
                    info["need_taint"] = []
                    # 重定向相关信息
                    info["redirect"] = {}
                    info["redirect_code"] = None
                    info["redirect_file"] = None
                    # 数据流约束与控制流约束
                    info["data_constraints"] = PFG.get_data_flow_constraints()
                    info["control_constraints"] = copy.deepcopy(control_constraints)
                    # 其余辅助信息
                    info["end_file"] = self.code_manager.get_filepath_by_id(end_node["id"])
                    info["funcs"] = copy.deepcopy(accessed_functions)
                    info["db_operation"] = copy.deepcopy(db_operation)
                    info["whole_path"] = PFG.get_visited_path()
                    # (1) 处理函数返回
                    if type == "start2return":
                        if stmt.node_type == "MethodReturn":
                            if stmt.return_result is not None:
                                info["return_result"] = PFG.stmt2json(stmt.return_result, True)
                    # (2) 处理sink函数
                    elif type == "start2sink":
                        info["sink"] = PFG.stmt2json(stmt, True)
                        info["sink_code"] = PFG.json2str(info["sink"])
                        info["need_taint"] = self.get_need_taint(info["sink"], PFG)
                    # (3) 处理重定向函数
                    elif type == "start2redirect":
                        info["redirect"] = PFG.stmt2json(stmt, True)
                        info["redirect_code"] = PFG.json2str(info["redirect"])
                        if stmt.method.shortName in self.taint_config["redirect"].keys():
                            arg_num_index = self.taint_config["redirect"][stmt.method.shortName]
                            if arg_num_index <= len(list(stmt.arguments.keys())):
                                arg_str_index = list(stmt.arguments.keys())[arg_num_index - 1]
                                redirect_argument = stmt.arguments[arg_str_index]
                                if redirect_argument is not None:
                                    redirect_pfg_node = self.process_stmt_data(redirect_argument, summary["start_cpg_id"], PFG, {"nodes": [], "field_edges": []}, ignore_none = True, add_node_flag = True)
                                    if redirect_pfg_node is not None:
                                        if redirect_pfg_node.value is not None:
                                            info["redirect_file"] = redirect_pfg_node.value
                    # 保存摘要信息
                    if not (type == "start2sink" and info["need_taint"] == []):
                        with open(sub_summary_path, "w", encoding = "utf-8") as f:
                            json.dump(info, f, ensure_ascii = False, indent = 4)

    def para2arg(self, info: any, parameter_map: dict):
        # 将摘要中的形参转为实参
        if isinstance(info, dict):
            for argument_index in parameter_map.keys():
                if info == parameter_map[argument_index]["parameter"]:
                    info = copy.deepcopy(parameter_map[argument_index]["argument"])
                    return
            for k in info.keys():
                self.para2arg(info[k], parameter_map)
        elif isinstance(info, list):
            for i in range(len(info)):
                self.para2arg(info[i], parameter_map)
        else:
            return
    
    def two_para2arg(self, info: dict, parameter_map: dict, PFG: PointerFlowGraph):
        # 将形参转换为实参,再使用真实表达式进行二次转换
        data = copy.deepcopy(info)
        self.para2arg(data, parameter_map)
        stmt = self.joern_server.json2stmt(data)
        data = PFG.stmt2json(stmt, True)
        return data

    def hava_parameter(self, info: any, parameter_map: dict, just_obj = False):
        # 判断一个表达式中是否含有参数
        if isinstance(info, dict):
            for argument_index in parameter_map.keys():
                if (info == parameter_map[argument_index]["parameter"]) and (not just_obj or (parameter_map[argument_index]["argument"]["node_type"] == "Object" and just_obj)):
                    return True
            for k in info.keys():
                if self.hava_parameter(info[k], parameter_map):
                    return True
        elif isinstance(info, list):
            for i in range(len(info)):
                if self.hava_parameter(info[i], parameter_map):
                    return True
        return False

    def get_parameter_map(self, call_stmt, PFG: PointerFlowGraph):
        # 获取实参-形参映射关系
        parameter_map = dict()
        if call_stmt is not None:
            if call_stmt.method is not None and call_stmt.arguments is not None:
                for argument_index in call_stmt.arguments.keys():
                    if argument_index in call_stmt.method.parameters.keys():
                        if argument_index not in parameter_map.keys():
                            parameter_map[argument_index] = dict()
                            parameter_map[argument_index]["argument"] = PFG.stmt2json(call_stmt.arguments[argument_index]) # 实参
                            parameter_map[argument_index]["parameter"] = PFG.stmt2json(call_stmt.method.parameters[argument_index]) # 形参
        return parameter_map

    def get_func_summary_root(self, stmt):
        # 获取函数的摘要地址
        have_summary = False
        func_summary_root = ""
        if stmt.method is not None:
            if stmt.method.shortName is not None:
                func_summary_root = os.path.join(self.func_path, stmt.method.shortName)
                if os.path.exists(func_summary_root):
                    have_summary = True
        return have_summary, func_summary_root

    def sort_nodes(self, ids: list, type: str):
        # 排序节点
        new_ids = list()
        nodes = list()
        new_nodes = list()
        for id in ids:
            node = self.joern_server.find_cpg_node_by_id(id)
            if node is not None and isinstance(node, dict):
                nodes.append(node)
            else:
                self.log_manager.log_info(f'Parsing Node Error: {id}', False, 3, True)
        if type == "source":
            sources = copy.deepcopy(self.source_funcs)
            sources.extend(self.source_vars)
            for source in sources:
                for node in nodes:
                    if str(node["code"]).find(source) != -1 and node["id"] not in new_ids:
                        new_ids.append(node["id"])
                        new_nodes.append(node)
        elif type == "sink":
            for sink in self.sinks:
                for node in nodes:
                    if str(node["code"]).find(sink) != -1 and node["id"] not in new_ids:
                        new_ids.append(node["id"])
                        new_nodes.append(node)
        for id in ids:
            if id not in new_ids:
                new_ids.append(id)
        return new_ids, new_nodes

    def forward_analysis(self, start_cpg_node: dict, init_call_stmt = None, analyze_all = False, node_id = None):
        # 正向分析获取摘要信息
        self.init_taint_analysis(start_cpg_node["id"])
        PFG = self.init_taint_PFG("all", start_cpg_node["id"], None, [])
        summary_root, need_analysis = self.init_summary(start_cpg_node, init_call_stmt, PFG, analyze_all, node_id)
        if need_analysis:
            init_db_operation = {"hava_write": False, "cpg_ids": [], "db_triples": []}
            self.worklist.append((start_cpg_node, PFG, start_cpg_node["id"], [], [], init_db_operation))
            while self.worklist != []:
                node_or_stmt, PFG_in, code_block_id, temp_accessed_functions, temp_control_constraints, temp_db_operation = self.worklist.pop()
                accessed_functions = copy.deepcopy(temp_accessed_functions) # 访问过了的函数fullname列表
                control_constraints = copy.deepcopy(temp_control_constraints) # 控制流约束条件列表
                db_operation = copy.deepcopy(temp_db_operation) # 数据操作
                if node_or_stmt is not None:
                    stmt = None; cpg_node = None; cpg_id = None; stmt_source = "node"
                    if isinstance(node_or_stmt, dict):
                        cpg_node = node_or_stmt; cpg_id = cpg_node["id"]
                        self.log_manager.log_info(f'Analyzing CPG Node: [namespace: {code_block_id}] [cpg id: {cpg_id}] [code: {cpg_node["code"]}]', False, 3)
                    else:
                        stmt_source = "stmt"
                        stmt = node_or_stmt; cpg_id = stmt.cpg_id
                        self.log_manager.log_info(f'Analyzing Stmt: [namespace: {code_block_id}] [cpg id: {cpg_id}] [code: {stmt.code}]', False, 3)
                    if cpg_node is None and stmt is None:
                        continue
                    self.block_parent_block_map[str(cpg_id)] = code_block_id
                    if not self.at_fixpoint(code_block_id, cpg_id, PFG_in, stmt_source):
                        PFG_in.visited.append(cpg_id)
                        call_stmts = list()
                        if isinstance(node_or_stmt, dict):
                            stmt = self.joern_server.parse_stmt(cpg_node)
                            self.extract_calls(stmt, call_stmts)
                        else:
                            cpg_node = self.joern_server.find_cpg_node_by_id(cpg_id)
                        # 处理当前语句中的所有函数调用语句
                        if call_stmts != []:
                            if stmt.node_type not in ["ObjCall", "CommonCall"]:
                                call_stmts.insert(0, stmt)
                            next_stmt = copy.deepcopy(call_stmts[0])
                            for i in range(1, len(call_stmts)):
                                call_stmt = call_stmts[i]
                                self.next_stmt_map[str(call_stmt.cpg_id)] = next_stmt
                                next_stmt = copy.deepcopy(call_stmt)
                            self.worklist.append((call_stmts[-1], PFG_in, code_block_id, accessed_functions, control_constraints, db_operation))
                        else:
                            # 分析当前语句
                            PFG_out = self.analyze_stmt(stmt, PFG_in, code_block_id, True)
                            # 收集上下文信息
                            contexts = list()
                            contexts.append({"PFG":PFG_out,"funcs":accessed_functions,"cons":control_constraints,"db_op":db_operation})
                            # 寻找后继节点
                            successors = list()
                            if stmt.node_type in ["ObjCall", "CommonCall"]:
                                self.collect_db_triples(db_operation, cpg_node, PFG_out, False)
                                external_flag, real_full_name = self.joern_server.is_external(cpg_node)
                                accessed_functions.append(real_full_name)
                                if real_full_name in self.sinks:
                                    # 记录sink函数
                                    self.record_summary("start2sink", summary_root, cpg_node, stmt, PFG_out, db_operation, control_constraints, accessed_functions)
                                elif real_full_name in self.redirects:
                                    # 记录redirect函数
                                    self.record_summary("start2redirect", summary_root, cpg_node, stmt, PFG_out, db_operation, control_constraints, accessed_functions)
                                # 分析到当前需要的sink时,停止后续分析(但对于函数仍然需要完全分析)
                                if stmt is not None and node_id is not None:
                                    if not analyze_all and stmt.cpg_id == node_id:
                                        continue
                                have_summary, func_summary_root = self.get_func_summary_root(stmt)
                                if not external_flag and not have_summary:
                                    # 分析未记录的可访问函数
                                    method_cpg_id, method_successors = self.joern_server.find_call_edge_successors(real_full_name)
                                    if len(method_successors) >= 1:
                                        func_taint_manager = ForwardAnalyzer(self.config_file, self.joern_server, self.page_manager, self.model_manager, self.log_manager, self.s2_handler)
                                        func_taint_manager.forward_analysis(method_successors[0], stmt, True, node_id) # 函数默认进行完整分析
                                    if len(method_successors) > 1:
                                        self.log_manager.log_info(f'Find more than one successors!', False, 3)
                                        self.log_manager.log_result(f"method_cpg_id_{method_cpg_id}_successors", method_successors)
                                if not external_flag:
                                    if os.path.exists(func_summary_root):
                                        # 使用记录的摘要信息
                                        find_sink, contexts = self.merge_summary(code_block_id, stmt, summary_root, func_summary_root, PFG_out, accessed_functions, control_constraints, db_operation, node_id)
                                        # 发现函数内部有当前需要的sink时,停止后续分析
                                        if find_sink:
                                            continue
                                else:
                                    # 分析内置函数
                                    self.taint_analysiss("all", stmt, PFG_out, code_block_id)
                                # 根据已经记录的语句顺序处理后续语句
                                if str(cpg_id) in self.next_stmt_map.keys():
                                    next_stmt = self.next_stmt_map[str(cpg_id)]
                                    for context in contexts:
                                        self.worklist.append((next_stmt, context["PFG"], code_block_id, context["funcs"], context["cons"], context["db_op"]))
                                    continue
                            if contexts == []:
                                contexts.append({"PFG":PFG_out,"funcs":accessed_functions,"cons":control_constraints,"db_op":db_operation})
                            successors = self.joern_server.find_cfg_successors(cpg_node)
                            if successors != []:
                                # 检查控制结构的条件
                                is_branch = False
                                if stmt.node_type == "ControlStructure":
                                    for context in contexts:
                                        successors, condition_dicts = self.select_successors(stmt, cpg_node, successors, context["PFG"], code_block_id)
                                        if stmt.controlStructureType in ["IF", "SWITCH"]:
                                            is_branch = True
                                            for index in range(0, min(len(successors), len(condition_dicts))):
                                                PFG_branch = self.record_condition(condition_dicts[index], context["PFG"], code_block_id)
                                                PFG_branch = self.copy_map_info(PFG_branch, index)
                                                branch_control_constraints = self.record_constraints(context["cons"], condition_dicts[index], PFG_branch)
                                                self.worklist.append((successors[index], PFG_branch, code_block_id, context["funcs"], branch_control_constraints, context["db_op"]))
                                if is_branch:
                                    continue
                                for context in contexts:
                                    for index in range(0, len(successors)):
                                        self.worklist.append((successors[index], self.copy_map_info(context["PFG"], index), code_block_id, context["funcs"], context["cons"], context["db_op"]))
                            else:
                                # 处理Return Edge(无论一个函数是否有返回值,在这里都被转换为了相同的处理)
                                parent_block_id = self.block_parent_block_map[str(code_block_id)]
                                if str(code_block_id) in self.next_stmt_map.keys():
                                    # 有记录下一条语句
                                    next_stmt = self.next_stmt_map[str(code_block_id)]
                                    for context in contexts:
                                        self.worklist.append((next_stmt, context["PFG"], parent_block_id, context["funcs"], context["cons"], context["db_op"]))
                                else:
                                    # 未记录下一条语句
                                    end_flag = True # 是否运行结束
                                    parent_cpg_node = self.joern_server.find_cpg_node_by_id(code_block_id) # 注意这里不能用parent_block_id
                                    if isinstance(parent_cpg_node, dict):
                                        if "_label" in parent_cpg_node.keys():
                                            if parent_cpg_node["_label"] != "CONTROL_STRUCTURE":
                                                successors = self.joern_server.find_cfg_successors(parent_cpg_node)
                                    if successors != []:
                                        for context in contexts:
                                            for index in range(0, len(successors)):
                                                if successors[index]["id"] not in context["PFG"].visited: # 避免重复分析
                                                    self.worklist.append((successors[index], self.copy_map_info(context["PFG"], index), parent_block_id, context["funcs"], context["cons"], context["db_op"]))
                                                    end_flag = False
                                    if end_flag or stmt.node_type == "MethodReturn":
                                        # 记录函数返回(部分函数可能没有return语句)
                                        self.record_summary("start2return", summary_root, cpg_node, stmt, PFG_out, db_operation, control_constraints, accessed_functions)