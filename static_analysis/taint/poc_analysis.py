import os
import copy
import sys
from base_analysis import BaseAnalyzer
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pfg.pointer_flow_graph import PointerFlowGraph
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class PoCAnalyzer(BaseAnalyzer):
    def __init__(self, joern_server, page_manager, model_manager, log_manager, s2_handler = None):
        super().__init__(joern_server, page_manager, model_manager, log_manager, s2_handler)

    def record_taint_info(self, processed_paths: list, PFG: PointerFlowGraph, start_cpg_node: dict, accessed_functions: list, interest_codes: list, db_operation: dict, taint_infos: list):
        # 记录污点信息
        visited_path = PFG.get_visited_path()
        if visited_path not in processed_paths:
            processed_paths.append(visited_path)
            taint_info = dict()
            taint_info["Tainted_Parameters"] = list(set(PFG.get_tainted_parameters()))
            taint_info["Vuln_Codes"] = self.code_manager.collect_vuln_codes(start_cpg_node, accessed_functions)
            if taint_info["Vuln_Codes"] == []:
                return
            taint_info["Core_Codes"] = self.code_manager.collect_core_codes(taint_info["Vuln_Codes"], taint_info["Tainted_Parameters"])
            taint_info["Interest_Codes"] = interest_codes
            taint_info["Redirect_URLs"] = copy.deepcopy(self.redirect_urls)
            taint_info["Conditions"] = copy.deepcopy(self.conditions)
            taint_info["User_Input"] = PFG.get_user_input_structure()
            taint_info["DB_Operation"] = db_operation
            taint_infos.append(taint_info)
            self.log_manager.log_info(f'Find One Vulnerable Path: {visited_path}', False, 3)
            self.log_manager.log_info(f'Tainted Parameters: {", ".join(taint_info["Tainted_Parameters"])}', False, 3)
            self.log_manager.log_info(f'Redirect Url: {str(taint_info["Redirect_URLs"])}', False, 3)
    
    def get_taint_parameters(self, vuln_type: str, start_cpg_node: dict, taint_cpg_node: dict, condition_node_dicts: list, index: str):
        # 获取被污染的参数(过程间分析)
        taint_infos = list() # 最终返回的结果
        if self.log_manager.get_log_result(f"taint_infos{index}"):
            return self.log_manager.get_log_result(f"taint_infos{index}")
        processed_paths = list() # 已经处理过了的路径列表
        self.init_taint_analysis(start_cpg_node[NodeField.ID])
        init_db_operation = {"hava_write": False, "cpg_ids": [], "db_triples": []}
        PFG = self.init_taint_PFG(vuln_type, start_cpg_node[NodeField.ID], taint_cpg_node, condition_node_dicts)
        self.worklist.append((start_cpg_node, PFG, start_cpg_node[NodeField.ID], [], [], init_db_operation))
        while self.worklist != []:
            node_or_stmt, PFG_in, code_block_id, temp_accessed_functions, temp_interest_codes, temp_db_operation = self.worklist.pop()
            accessed_functions = copy.deepcopy(temp_accessed_functions) # 访问过了的函数fullname列表
            interest_codes = copy.deepcopy(temp_interest_codes) # 感兴趣的代码列表
            db_operation = copy.deepcopy(temp_db_operation) # 数据操作
            if node_or_stmt is not None:
                stmt = None; cpg_node = None; cpg_id = None; stmt_source = "node"
                if isinstance(node_or_stmt, dict):
                    cpg_node = node_or_stmt; cpg_id = cpg_node[NodeField.ID]
                    self.log_manager.log_info(f'Analyzing CPG Node: [namespace: {code_block_id}] [cpg id: {cpg_id}] [code: {cpg_node["code"]}]', False, 3)
                else:
                    stmt_source = "stmt"
                    stmt = node_or_stmt; cpg_id = stmt.cpg_id
                    self.log_manager.log_info(f'Analyzing Stmt: [namespace: {code_block_id}] [cpg id: {cpg_id}] [code: {stmt.code}]', False, 3)
                self.block_parent_block_map[str(cpg_id)] = code_block_id
                if not self.at_fixpoint(code_block_id, cpg_id, PFG_in, stmt_source):
                    if cpg_id not in PFG_in.visited:
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
                        self.worklist.append((call_stmts[-1], PFG_in, code_block_id, accessed_functions, interest_codes, db_operation))
                    else:
                        # 分析当前语句
                        PFG_out = self.analyze_stmt(stmt, PFG_in, code_block_id)
                        collect_flag = self.code_manager.collect_interest_codes(self.interest_flag, interest_codes, cpg_node)
                        # 寻找后继节点
                        successors = list()
                        if stmt.node_type in ["ObjCall", "CommonCall"]:
                            self.collect_db_triples(db_operation, cpg_node, PFG_out)
                            external_flag, real_full_name = self.joern_server.is_external(cpg_node)
                            if not external_flag:
                                # 处理Call Edge
                                # 收集访问的函数名称
                                if real_full_name:
                                    if real_full_name not in accessed_functions:
                                        accessed_functions.append(real_full_name)
                                method_cpg_id, successors = self.joern_server.find_call_edge_successors(real_full_name)
                                PFG_out.visited.append(method_cpg_id)
                                if successors != []:
                                    for successor in successors:
                                        self.worklist.append((successor, PFG_out, stmt.cpg_id, accessed_functions, interest_codes, db_operation))
                                    continue
                            else:
                                # 处理外部函数
                                self.taint_analysiss(vuln_type, stmt, PFG_out, code_block_id)
                                if self.interest_flag:
                                    if not collect_flag:
                                        self.code_manager.collect_interest_codes(self.interest_flag, interest_codes, cpg_node)
                                    self.record_taint_info(processed_paths, PFG_out, start_cpg_node, accessed_functions, interest_codes, db_operation, taint_infos)
                                    continue
                            # 处理无法获取到Call Edge的函数
                            if str(cpg_id) in self.next_stmt_map.keys():
                                next_stmt = self.next_stmt_map[str(cpg_id)]
                                self.worklist.append((next_stmt, PFG_out, code_block_id, accessed_functions, interest_codes, db_operation))
                                continue
                        successors = self.joern_server.find_cfg_successors(cpg_node)
                        if successors != []:
                            # 检查控制结构的条件
                            if stmt.node_type == "ControlStructure":
                                successors, condition_dicts = self.select_successors(stmt, cpg_node, successors, PFG_out, code_block_id)
                                if stmt.controlStructureType in ["IF", "SWITCH"]:
                                    for successor, condition_dict in zip(successors, condition_dicts):
                                        PFG_branch = self.record_condition(condition_dict, PFG_out, code_block_id)
                                        self.worklist.append((successor, PFG_branch, code_block_id, accessed_functions, interest_codes, db_operation))
                                    continue
                            for successor in successors:
                                self.worklist.append((successor, PFG_out, code_block_id, accessed_functions, interest_codes, db_operation))
                        else:
                            # 处理Return Edge(无论一个函数是否有返回值,在这里都被转换为了相同的处理)
                            parent_block_id = self.block_parent_block_map[str(code_block_id)]
                            if str(code_block_id) in self.next_stmt_map.keys():
                                # 有记录下一条语句
                                next_stmt = self.next_stmt_map[str(code_block_id)]
                                self.worklist.append((next_stmt, PFG_out, parent_block_id, accessed_functions, interest_codes, db_operation))
                            else:
                                # 未记录下一条语句
                                end_flag = True # 是否运行结束
                                parent_cpg_node = self.joern_server.find_cpg_node_by_id(code_block_id) # 注意这里不能用parent_block_id
                                if isinstance(parent_cpg_node, dict):
                                    if "_label" in parent_cpg_node.keys():
                                        if parent_cpg_node["_label"] != "CONTROL_STRUCTURE":
                                            successors = self.joern_server.find_cfg_successors(parent_cpg_node)
                                if successors != []:
                                    for successor in successors:
                                        if successor[NodeField.ID] not in PFG_out.visited: # 避免重复分析
                                            self.worklist.append((successor, PFG_out, parent_block_id, accessed_functions, interest_codes, db_operation))
                                            end_flag = False
                                if end_flag:
                                    self.record_taint_info(processed_paths, PFG_out, start_cpg_node, accessed_functions, interest_codes, db_operation, taint_infos)
        self.log_manager.log_result(f"taint_infos{index}", taint_infos)
        return taint_infos