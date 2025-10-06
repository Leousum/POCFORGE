import copy
from static_analysis.taint.base_analysis import BaseAnalyzer

class BackwardAnalyzer(BaseAnalyzer):
    def __init__(self, config_file, joern_server, page_manager, model_manager, log_manager, s2_handler = None):
        super().__init__(config_file, joern_server, page_manager, model_manager, log_manager, s2_handler)
    
    def in_control(self, cpg_node: dict):
        # 判断当前分析节点是否处于控制结构语句中
        in_control = False
        lineNumber = None
        control_sanitizers = list(self.taint_config["control_sanitizers"].keys())
        parent_node, is_sanitized = self.joern_server.check_astParent(cpg_node, control_sanitizers)
        if not is_sanitized:
            if isinstance(parent_node, dict) and "_label" in parent_node.keys() and "lineNumber" in parent_node.keys():
                if parent_node["_label"] == "CONTROL_STRUCTURE":
                    in_control = True
                    lineNumber = str(parent_node["lineNumber"])
        return in_control, lineNumber, is_sanitized

    def analyze_method_parameter(self, workstack: list, cpg_node: dict, arg_map: dict, call_info: dict, find_source:bool, is_possible:bool):
        # 分析函数形参
        at_end = True
        if str(cpg_node["id"]) in arg_map.keys():
            # 继续分析实参
            if arg_map[str(cpg_node["id"])] is not None:
                predecessor_node = self.joern_server.find_cpg_node_by_id(arg_map[str(cpg_node["id"])])
                if isinstance(predecessor_node, dict):
                    at_end = False
                    new_call_info = copy.deepcopy(call_info)
                    if new_call_info["call_ids"]:
                        new_call_info["call_ids"].pop()
                    workstack.append((predecessor_node, arg_map, new_call_info, find_source, is_possible))
        else:
            # 继续分析函数的所有调用点对应的实参
            # 获取形参索引
            parameter_indexs = list()
            if "name" in cpg_node.keys():
                parameter_indexs.append(cpg_node["name"])
            if "index" in cpg_node.keys():
                parameter_indexs.append(str(cpg_node["index"]))
            # 获取实参索引
            if parameter_indexs:
                method_node = self.joern_server.find_astParent_until_top(cpg_node)
                if isinstance(method_node, dict):
                    call_sites = self.joern_server.find_call_sites(method_node)
                    for call_site in call_sites:
                        if isinstance(call_site, dict) and "id" in call_site.keys():
                            if not self.in_call_statck(call_site, call_info):
                                argument_nodes = self.joern_server.find_method_call_arguments(call_site)
                                for argument_node in argument_nodes:
                                    if isinstance(argument_node, dict):
                                        if "argumentIndex" in argument_node.keys():
                                            if str(argument_node["argumentIndex"]) in parameter_indexs:
                                                at_end = False
                                                new_call_info = self.collect_call_stack(call_site, call_info)
                                                if new_call_info["call_ids"]:
                                                    new_call_info["call_ids"].pop()
                                                new_call_info["call_ids"].append(call_site["id"])
                                                workstack.append((argument_node, arg_map, new_call_info, find_source, is_possible))
                                                break
                                        elif "argumentName" in argument_node.keys():
                                            if str(argument_node["argumentName"]) in parameter_indexs:
                                                at_end = False
                                                new_call_info = self.collect_call_stack(call_site, call_info)
                                                if new_call_info["call_ids"]:
                                                    new_call_info["call_ids"].pop()
                                                new_call_info["call_ids"].append(call_site["id"])
                                                workstack.append((argument_node, arg_map, new_call_info, find_source, is_possible))
                                                break
        return at_end

    def analyze_method_call(self, workstack: list, cpg_node: dict, stmt: any, arg_map: dict, call_info: dict, find_source, is_possible):
        # 分析函数调用
        at_end = True
        external_flag, real_full_name = self.joern_server.is_external(cpg_node)
        short_name = None
        if stmt.method is not None:
            if stmt.method.shortName is not None:
                short_name = stmt.method.shortName
        if not external_flag:
            if short_name is not None and short_name in self.taint_config["sources"].keys():
                find_source = True
            else:
                # 记录新的形参=>实参映射关系
                if stmt.method is not None and stmt.arguments is not None:
                    for parameter_index in stmt.method.parameters.keys():
                        parameter_stmt = stmt.method.parameters[parameter_index] # 形参
                        if hasattr(parameter_stmt, "cpg_id"):
                            if parameter_stmt.cpg_id is not None:
                                arg_map[str(parameter_stmt.cpg_id)] = None # 先置为None以免重复使用相同实参
                                if parameter_index in stmt.arguments.keys():
                                    argument_stmt = stmt.arguments[parameter_index] # 实参
                                    if hasattr(argument_stmt, "cpg_id"):
                                        if argument_stmt.cpg_id is not None:
                                            arg_map[str(parameter_stmt.cpg_id)] = str(argument_stmt.cpg_id)
                # 从函数返回值开始分析
                data_nodes = self.joern_server.get_method_return_data_nodes(real_full_name)
                for node in data_nodes:
                    at_end = False
                    new_call_info = copy.deepcopy(call_info)
                    new_call_info["call_ids"].append(cpg_node["id"])
                    workstack.append((node, arg_map, new_call_info, find_source, is_possible))
        else:
            if short_name is not None:
                if short_name in self.taint_config["sources"].keys():
                    find_source = True
                elif short_name in self.taint_config["sanitizer"].keys():
                    is_possible = False
                elif short_name in self.taint_config["sinks"].keys() and self.at_first:
                    self.at_first = False
                    argument_index = 1 # TODO:基本所有sink的参数都在第1位
                    if short_name in self.taint_config["sinks"].keys():
                        argument_index = self.taint_config["sinks"][short_name]["index"]
                    argument_nodes = self.joern_server.find_method_call_arguments(cpg_node)
                    add_flag = False
                    # 首次遇到sink函数时,只检查处于危险位置的变量
                    for argument_node in argument_nodes:
                        if isinstance(argument_node, dict) and "argumentIndex" in argument_node.keys():
                            if str(argument_node["argumentIndex"]) == str(argument_index):
                                add_flag = True
                                at_end = False
                                workstack.append((argument_node, arg_map, call_info, find_source, is_possible))
                                break
                    if not add_flag:
                        if isinstance(argument_index, int) and len(argument_nodes) >= argument_index and argument_index >= 1:
                            if isinstance(argument_nodes[argument_index - 1], dict):
                                add_flag = True
                                at_end = False
                                workstack.append((argument_nodes[argument_index - 1], arg_map, call_info, find_source, is_possible))
                elif short_name in self.taint_config["transfers"].keys():
                    if self.taint_config["transfers"][short_name]["to"] == "result":
                        from_index = self.taint_config["transfers"][short_name]["from"]
                        if isinstance(from_index, int):
                            argument_nodes = self.joern_server.find_method_call_arguments(cpg_node)
                            add_flag = False
                            for argument_node in argument_nodes:
                                if isinstance(argument_node, dict) and "argumentIndex" in argument_node.keys():
                                    if str(argument_node["argumentIndex"]) == str(from_index):
                                        add_flag = True
                                        at_end = False
                                        workstack.append((argument_node, arg_map, call_info, find_source, is_possible))
                                        break
                            if not add_flag:
                                if len(argument_nodes) >= from_index and from_index >= 1:
                                    if isinstance(argument_nodes[from_index - 1], dict):
                                        add_flag = True
                                        at_end = False
                                        workstack.append((argument_nodes[from_index - 1], arg_map, call_info, find_source, is_possible))
                else:
                    # 检查传入参数是否可能被污染
                    argument_nodes = self.joern_server.find_method_call_arguments(cpg_node)
                    for argument_node in argument_nodes:
                        if isinstance(argument_node, dict):
                            at_end = False
                            workstack.append((argument_node, arg_map, call_info, find_source, is_possible))
                    # 记录函数信息
                    self.update_taint_config(stmt)
        return at_end, find_source, is_possible

    def analyze_variable(self, workstack: list, cpg_node: dict, arg_map: dict, call_info: dict, find_source, is_possible):
        # 分析普通变量
        at_end = True
        in_control, lineNumber, is_sanitized = self.in_control(cpg_node)
        if not is_sanitized:
            reaching_nodes = self.joern_server.find_reachingDefIn_nodes(cpg_node)
            for reaching_node in reaching_nodes:
                if in_control:
                    if "lineNumber" in reaching_node.keys():
                        if str(reaching_node["lineNumber"]) == lineNumber:
                            if not self.joern_server.in_assignment(reaching_node): # 防止忽略($x = $y) !== Null中的赋值语句
                                continue
                at_end = False
                workstack.append((reaching_node, arg_map, call_info, find_source, is_possible))
        else:
            is_possible = False
        return at_end, find_source, is_possible
    
    def analyze_obj_field(self, workstack: list, cpg_node: dict, stmt: any, arg_map: dict, call_info: dict, find_source, is_possible):
        # 处理全局变量
        at_end = True
        in_control, lineNumber, is_sanitized = self.in_control(cpg_node)
        is_global = self.is_global_var(stmt)
        if is_global:
            is_possible = False # 默认PHP全局变量不可能含有污点数据
        else:
            if not is_sanitized:
                reaching_nodes = self.joern_server.find_reachingDefIn_nodes(cpg_node)
                for reaching_node in reaching_nodes:
                    if in_control:
                        if "lineNumber" in reaching_node.keys():
                            if str(reaching_node["lineNumber"]) == lineNumber:
                                if not self.joern_server.in_assignment(reaching_node):
                                    continue
                    at_end = False
                    workstack.append((reaching_node, arg_map, call_info, find_source, is_possible))
            else:
                is_possible = False
        return at_end, find_source, is_possible
    
    def analyze_operation(self, workstack: list, cpg_node: dict, stmt: any, arg_map: dict, call_info: dict, find_source, is_possible):
        # 处理数据操作
        at_end = True
        in_control, lineNumber, is_sanitized = self.in_control(cpg_node)
        if stmt.operator == "<operator>.indexAccess":
            is_global = self.is_global_var(stmt)
            if is_global:
                find_source = True # 对于$_GET['x']变量,还是需要继续分析其值是否被清理
            if not is_sanitized:
                reaching_nodes = self.joern_server.find_reachingDefIn_nodes(cpg_node)
                for reaching_node in reaching_nodes:
                    if in_control:
                        if "lineNumber" in reaching_node.keys():
                            if str(reaching_node["lineNumber"]) == lineNumber:
                                if not self.joern_server.in_assignment(reaching_node):
                                    continue
                    at_end = False
                    workstack.append((reaching_node, arg_map, call_info, find_source, is_possible))
            else:
                is_possible = False
        elif stmt.operator in ["<operator>.assignmentPlus", "<operator>.assignmentConcat", "<operator>.concat", "<operator>.addition",
                                "<operator>.coalesce", "<operator>.plus", "<operator>.conditional", "<operator>.assignmentCoalesce", "encaps"]:
            # 我们关注的Web漏洞只和字符串运算有关,因此只用关注这些和字符串相关的运算
            for i in range(0, len(stmt.operands)):
                operand = stmt.operands[i]
                if stmt.operator == "<operator>.conditional" and i == 0:
                    continue # 条件表达式第一项数据没有必要处理
                if hasattr(operand, "cpg_id"):
                    operand_cpg_node = self.joern_server.find_cpg_node_by_id(operand.cpg_id)
                    at_end = False
                    workstack.append((operand_cpg_node, arg_map, call_info, find_source, is_possible))
        else:
            # 其它运算会被视为不存在漏洞(web漏洞一般由字符串注入导致)
            is_possible = False
        return at_end, find_source, is_possible

    def in_vuln_infos(self, vuln_infos: list, call_info: dict):
        # 检查一个调用栈是否已经被分析过
        if isinstance(vuln_infos, list):
            for vuln_info in vuln_infos:
                if isinstance(vuln_info, dict) and "path" in vuln_info.keys():
                    if isinstance(call_info, dict) and "path" in call_info.keys():
                        if call_info["path"] == vuln_info["path"]:
                            return True
        return False

    def in_call_statck(self, cpg_node: dict, call_info: dict):
        # 检查一个CPG Node是否已经在调用栈中
        if isinstance(cpg_node, dict) and "id" in cpg_node.keys():
            for item in call_info["call_stack"]:
                if isinstance(item["call_node"], dict):
                    if "id" in item["call_node"].keys():
                        if item["call_node"]["id"] == cpg_node["id"]:
                            return True
                if isinstance(item["first_node"], dict):
                    if "id" in item["first_node"].keys():
                        if item["first_node"]["id"] == cpg_node["id"]:
                            return True
                if isinstance(item["method_node"], dict):
                    if "id" in item["method_node"].keys():
                        if item["method_node"]["id"] == cpg_node["id"]:
                            return True
        return False

    def collect_call_stack(self, call_node: dict, call_info_old: dict, add_end = False):
        # 收集调用栈信息
        call_info = copy.deepcopy(call_info_old)
        if isinstance(call_info, dict):
            if "call_stack" not in call_info.keys():
                call_info["call_stack"] = list()
        else:
            call_info = dict()
            call_info["path"] = ""
            call_info["taint_data"] = None
            call_info["call_stack"] = list()
            call_info["call_ids"] = list()
        method_node = self.joern_server.find_belong_method(call_node)
        if not self.in_call_statck(method_node, call_info):
            if isinstance(method_node, dict) and "id" in method_node.keys():
                # 如果属于函数,就保存此函数的信息
                item = dict()
                item["call_node"] = copy.deepcopy(call_node)
                item["method_node"] = copy.deepcopy(method_node)
                item["first_node"] = None
                if add_end:
                    call_info["call_stack"].append(item)
                    if isinstance(item["call_node"], dict) and "id" in item["call_node"].keys():
                        call_info["path"] = call_info["path"] + "=>" + str(item["method_node"]["id"]) + "to" + str(item["call_node"]["id"])
                else:
                    call_info["call_stack"].insert(0, item)
                    if isinstance(item["call_node"], dict) and "id" in item["call_node"].keys():
                        call_info["path"] = str(item["method_node"]["id"]) + "to" + str(item["call_node"]["id"]) + "=>" + call_info["path"]
            else:
                # 如果不属于函数,就找到所处文件第一条语句
                first_node = self.joern_server.find_dominated_first_node(call_node)
                if isinstance(first_node, dict) and "id" in first_node.keys():
                    item = dict()
                    item["call_node"] = copy.deepcopy(call_node)
                    item["first_node"] = copy.deepcopy(first_node)
                    item["method_node"] = None
                    if add_end:
                        call_info["call_stack"].append(item)
                        if isinstance(item["call_node"], dict) and "id" in item["call_node"].keys():
                            call_info["path"] = call_info["path"] + "=>" + str(item["first_node"]["id"]) + "to" + str(item["call_node"]["id"])
                    else:
                        call_info["call_stack"].insert(0, item)
                        if isinstance(item["call_node"], dict) and "id" in item["call_node"].keys():
                            call_info["path"] = str(item["first_node"]["id"]) + "to" + str(item["call_node"]["id"]) + "=>" + call_info["path"]
                else:
                    item = dict()
                    item["call_node"] = copy.deepcopy(call_node)
                    item["first_node"] = copy.deepcopy(call_node)
                    item["method_node"] = None
                    if add_end:
                        call_info["call_stack"].append(item)
                        if isinstance(item["call_node"], dict) and "id" in item["call_node"].keys():
                            call_info["path"] = call_info["path"] + "=>" + str(item["call_node"]["id"])
                    else:
                        call_info["call_stack"].insert(0, item)
                        if isinstance(item["call_node"], dict) and "id" in item["call_node"].keys():
                            call_info["path"] = str(item["call_node"]["id"]) + "=>" + call_info["path"]
        return call_info

    def log_analyzing_info(self, cpg_node: dict, inedx):
        '''
        记录正在分析的节点信息
        '''
        self.log_manager.log_info(f'Backward Analyzing The Sink Point[{str(inedx + 1)}]', False, 0, True)
        content = ""
        if isinstance(cpg_node, dict):
            if "id" in cpg_node.keys() and "_label" in cpg_node.keys():
                content = f' [cpg id: {cpg_node["id"]}] [_label: {cpg_node["_label"]}]'
            if "code" in cpg_node.keys():
                content += f' [code: {cpg_node["code"]}]'
            if "filename" in cpg_node.keys():
                content += f' [filename: {cpg_node["filename"]}]'
            if "lineNumber" in cpg_node.keys():
                content += f' [lineNumber: {cpg_node["lineNumber"]}]'
            if self.joern_server is not None:
                content += f' [joern server point: {self.joern_server.joern_server_point}]'
        self.log_manager.log_info(content, False, 0, True)

    def backward_analysis(self, node_id: dict, index: int = 0):
        # 从sink调用点出发执行后向分析
        workstack = list()
        func_name = None
        vuln_infos = list()
        processed_ids = list() # 已处理CPG Node ID列表
        init_cpg_node = self.joern_server.find_cpg_node_by_id(node_id)

        if isinstance(init_cpg_node, dict):
            self.log_analyzing_info(init_cpg_node, index)

            init_call_info = self.collect_call_stack(init_cpg_node, {"path": "", "taint_data": None, "call_stack": [], "call_ids": []})
            if "methodFullName" in init_cpg_node.keys():
                func_name = init_cpg_node["methodFullName"]
            elif "name" in init_cpg_node.keys():
                func_name = init_cpg_node["name"]
            workstack.append((init_cpg_node, {}, init_call_info, False, True))
        self.at_first = True
        while workstack != []:
            at_end = True
            temp_cpg_node, temp_arg_map, temp_call_info, find_source, is_possible = workstack.pop()
            cpg_node = copy.deepcopy(temp_cpg_node)
            arg_map = copy.deepcopy(temp_arg_map) # 形参=>实参映射字典
            call_info = copy.deepcopy(temp_call_info) # 函数调用栈
            if isinstance(cpg_node, dict) and "id" in cpg_node.keys() and "_label" in cpg_node.keys():
                if cpg_node["id"] not in processed_ids and cpg_node["_label"] != "BLOCK" and cpg_node["code"] not in ["<empty>", ""]:
                    content = f'Analysing [cpg id: {cpg_node["id"]}] [_label: {cpg_node["_label"]}]'
                    if "code" in cpg_node.keys():
                        content += f' [code: {cpg_node["code"]}]'
                        call_info["taint_data"] = str(cpg_node["code"])
                    if "lineNumber" in cpg_node.keys():
                        content += f' [lineNumber: {cpg_node["lineNumber"]}]'
                    self.log_manager.log_info(content, False, self.joern_server.log_level, True)
                    processed_ids.append(cpg_node["id"])
                    if cpg_node["_label"] == "METHOD_PARAMETER_IN":
                        # 处理函数形参
                        at_end = self.analyze_method_parameter(workstack, cpg_node, arg_map, call_info, find_source, is_possible)
                    else:
                        stmt = self.joern_server.parse_stmt(cpg_node)
                        if stmt is not None:
                            if stmt.node_type in ["ObjCall", "CommonCall"]:
                                at_end, find_source, is_possible = self.analyze_method_call(workstack, cpg_node, stmt, arg_map, call_info, find_source, is_possible)
                            elif stmt.node_type in ["Variable", "PHPArray"]:
                                at_end, find_source, is_possible = self.analyze_variable(workstack, cpg_node, arg_map, call_info, find_source, is_possible)
                            elif stmt.node_type in ["Object", "Object_Field"]:
                                at_end, find_source, is_possible = self.analyze_obj_field(workstack, cpg_node, stmt, arg_map, call_info, find_source, is_possible)
                            elif stmt.node_type == "Operation":
                                if len(stmt.operands) <= 10:
                                    at_end, find_source, is_possible = self.analyze_operation(workstack, cpg_node, stmt, arg_map, call_info, find_source, is_possible)
                            elif stmt.node_type == "Literal":
                                is_possible = False
                    if at_end:
                        if is_possible and find_source: # 添加find_source表示执行更严格的后向分析
                            if stmt is not None:
                                if stmt.node_type == "Object_Field" and cpg_node["code"]:
                                    # 检查调用点附近全局变量是否被清理
                                    if call_info["call_stack"] and isinstance(call_info["call_stack"], list):
                                        item = call_info["call_stack"][0]
                                        if isinstance(item, dict) and "method_node" in item.keys():
                                            method_node = item["method_node"]
                                            if isinstance(method_node, dict):
                                                call_sites = self.joern_server.find_call_sites(method_node)
                                                for call_site in call_sites:
                                                    if isinstance(call_site, dict) and "id" in call_site.keys():
                                                        if not self.in_call_statck(call_site, call_info):
                                                            data_node = self.joern_server.find_dominated_data_node(call_site, cpg_node)
                                                            if data_node is not None:
                                                                at_end = False
                                                                new_call_info = self.collect_call_stack(call_site, call_info)
                                                                workstack.append((data_node, arg_map, new_call_info, find_source, is_possible))
                    if at_end:
                        if is_possible and find_source:
                            for id in call_info["call_ids"]:
                                current_call_node = self.joern_server.find_cpg_node_by_id(id)
                                if isinstance(current_call_node, dict) and "id" in current_call_node.keys():
                                    if not self.in_call_statck(current_call_node, call_info):
                                        call_info = self.collect_call_stack(current_call_node, call_info, True)
                            if not self.in_call_statck(cpg_node, call_info):
                                call_info = self.collect_call_stack(cpg_node, call_info, True)
                            call_info["path"] = call_info["path"].strip("=>")
                            if not self.in_vuln_infos(vuln_infos, call_info):
                                vuln_infos.append(call_info)
                                break # 找到source就结束,不必全部分析
        return func_name, vuln_infos