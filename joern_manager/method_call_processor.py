import copy
from typing import List

from method_return_processor import MethodReturnProcessor
from cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class MethodCallProcessor(MethodReturnProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)
    
    def find_method_call_nodes_by_name(self, short_name: str):
        '''
        根据方法名称找到所有函数调用语句节点
        '''
        method_call_nodes = []
        if short_name:
            nodes = self.find_nodes(
                cpg_type = NodeType.ALL,
                conditions = [f'node.{NodeField.NAME}=="{short_name}"'],
                restricts = []
            )
            method_call_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []

        return method_call_nodes
    
    def find_method_call_nodes_by_start_name(self, short_name: str):
        '''
        根据方法名称的起始字符串找到所有函数调用语句节点
        '''
        method_call_nodes = []
        if short_name:
            nodes = self.find_nodes(
                cpg_type = NodeType.ALL,
                conditions = [f'node.{NodeField.NAME}.{NodeMethod.STARTS_WITH}("{short_name}")'],
                restricts = []
            )
            method_call_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []

        return method_call_nodes
    
    def find_method_call_nodes_by_full_name(self, full_name: str):
        '''
        根据方法签名找到所有函数调用语句节点
        '''
        method_call_nodes = []
        if full_name:
            nodes = self.find_nodes(
                cpg_type = NodeType.ALL,
                conditions = [f'node.{NodeField.METHOD_FULL_NAME}=="{full_name}"'],
                restricts = []
            )
            method_call_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []

        return method_call_nodes

    def find_method_call_nodes_in_method(self, belong_method_full_name: str, target_method_full_name: str):
        '''
        在所属方法内部找到访问了指定方法签名的方法调用节点
        '''
        method_call_nodes = []
        if belong_method_full_name is not None and target_method_full_name is not None:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [f'node.{NodeField.FULL_NAME}=="{belong_method_full_name}"'],
                restricts = [NodeField.AST, NodeConstraint.IS_CALL, f'{NodeMethod.FILTER}(node=>node.{NodeField.METHOD_FULL_NAME}=="{target_method_full_name}")']
            )
            method_call_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return method_call_nodes

    def find_method_call_node_by_name(self, short_name: str):
        '''
        根据方法名称找到函数调用语句
        '''
        if short_name:
            nodes = self.find_nodes(
                cpg_type = NodeType.ALL,
                conditions = [f'node.{NodeField.NAME}=="{short_name}"'],
                restricts = ["take(5)"]
            )
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        return node
        return None
    
    def find_init_method_call_node(self, method_cpg_node: dict, init_class_name: str, is_patched: bool):
        '''
        查找构造方法的调用节点
        '''
        restricts = []
        if not isinstance(method_cpg_node, dict) or not init_class_name:
            return None

        # 获取方法体约束条件
        method_id = method_cpg_node.get(NodeField.ID, None)
        method_full_name = method_cpg_node.get(NodeField.FULL_NAME, None)
        if method_id is None and method_full_name is None:
            return None

        if is_patched:
            restricts.append(f'{NodeMethod.FILTER}(node=>node.{NodeField.FULL_NAME}=="{method_full_name}")')
        else:
            restricts.append(f"{NodeMethod.FILTER}(node=>node.{NodeField.ID}=={method_id})")
        
        init_class_name = init_class_name.strip(".")
        if "<init>" not in init_class_name:
            init_class_name = f"{init_class_name}.<init>"

        restricts.append(NodeField.AST)
        restricts.append(NodeConstraint.IS_CALL)
        restricts.append(f'{NodeMethod.FILTER}(node => node.{NodeField.METHOD_FULL_NAME}.{NodeMethod.CONTAINS}("{init_class_name}"))')
        restricts.append(f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER}).take(3)")

        nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [],
            restricts = restricts
        )
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict) and NodeField.ID in node.keys():
                    return node

        return None
    
    ### 根据调用方法和被调用的方法,以及调用方法的位置来筛选 (方法内的方法调用)
    def query_invocation_in_method(self, callee_name, method_full_name, line_number) -> list:
        query_stmt = []
        query_stmt.append(f"""var m = cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node => node.{NodeField.FULL_NAME} == "{method_full_name}")""")
        query_stmt.append(f"""m.flatMap(_.call).{NodeMethod.FILTER}(node => node.{NodeField.NAME} == "{callee_name}").l""")

        cpg_nodes = list()
        result_nodes = self.query(query_stmt)
        for cpg_node in result_nodes:
            if cpg_node[NodeField.LINE_NUMBER] ==line_number:
                cpg_nodes.append(cpg_node)

        return cpg_nodes

    def query_invocations_in_method(self, callee_name, method_full_name):
        query_stmt = []
        query_stmt.append(f"""var m = cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node => node.{NodeField.FULL_NAME} == "{method_full_name}")""")
        query_stmt.append(f"""m.flatMap(_.call).{NodeMethod.FILTER}(node => node.{NodeField.NAME} == "{callee_name}").l""")

        result_nodes = self.query(query_stmt)
        return result_nodes

    def query_all_invocations_in_method(self, method_full_name):
        query_stmt = []
        query_stmt.append(f"""var m = cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node => node.{NodeField.FULL_NAME} == "{method_full_name}")""")
        query_stmt.append(f"""m.{NodeField.AST}.{NodeConstraint.IS_CALL}.l""")
        result_nodes = self.query(query_stmt)
        return result_nodes
    
    ### 根据调用方法和被调用的方法,以及调用方法的位置来筛选 (方法外的方法调用)
    def query_invocation_outside_method(self, callee_name, class_fullName, line_number):
        query = f'''cpg.{NodeType.TYPE_DECL}.{NodeField.FULL_NAME}("{class_fullName}").method.{NodeType.CALL}.{NodeField.NAME}("{callee_name}").l.toJson'''
        try:
            query_result = self.joern_client.execute(query)["stdout"]
            query_result = query_result[query_result.find("=") + 1:].strip()
            nodes = self.str2list(query_result)
            self.log_manager.log_info(f"CPG Query Success: {query}", False, self.indent_level)

            for cpg_node in nodes:
                if cpg_node[NodeField.LINE_NUMBER] == line_number:
                    return cpg_node
        except Exception as e:
            self.log_manager.log_info(f"CPG Query Fail: {query}", False, self.indent_level)
            raise (e)
        return dict()

    def query_all_invocations_outside_Method(self, method_full_name):
        query_stmt = []
        query_stmt.append(f"""var m = cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node => node.{NodeField.FULL_NAME} == "{method_full_name}")""")
        query_stmt.append(f"""m.{NodeField.AST}.{NodeConstraint.IS_CALL}.l""")
        result_nodes = self.query(query_stmt)
        return result_nodes
    
    def query_invocations_outside_method(self, callee_name, class_fullName):
        query = f'''cpg.{NodeType.TYPE_DECL}.{NodeField.FULL_NAME}("{class_fullName}").method.{NodeType.CALL}.{NodeField.NAME}("{callee_name}").l.toJson'''
        try:
            query_result = self.joern_client.execute(query)["stdout"]
            query_result = query_result[query_result.find("=") + 1:].strip()
            nodes = self.str2list(query_result)
            self.log_manager.log_info(f"CPG Query Success: {query}", False, self.indent_level)

            return nodes
        except Exception as e:
            self.log_manager.log_info(f"CPG Query Fail: {query}", False, self.indent_level)
            raise (e)