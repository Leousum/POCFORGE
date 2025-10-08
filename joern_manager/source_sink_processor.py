import copy
from typing import List

from joern_manager.stmt_processor import StmtProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class SourceSinkProcessor(StmtProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level=0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def find_entry(self, class_name: str, method_name: str):
        '''
        根据类名称和方法名称查找方法的起始点作为分析的 Entry
        '''
        nodes = self.find_nodes(
            cpg_type=NodeType.ALL,
            conditions=[f"node.{NodeField.LOCATION}.{NodeField.CLASS_SHORT_NAME}==\"{class_name}\" && node.{NodeField.LOCATION}.{NodeField.METHOD_SHORT_NAME}==\"{method_name}\""],
            restricts=[f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})", "take(1)"]
        )
        if nodes != []:
            return nodes[0]
        return None

    def find_php_request_method_node(self):
        request_method_nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f'node.{NodeField.CODE} == "$_SERVER[\"REQUEST_METHOD\"]"'],
            restricts = ["take(1)"]
        )
        if request_method_nodes:
            return request_method_nodes[0]
        return None

    def find_user_input_nodes(self, php_global_vars: list, vuln_parameter: str):
        '''
        在有参数的情况下查找PHP程序中可能的用户输入节点
        '''
        restrict = f"{NodeMethod.FILTER}(node => ("
        for i in range(0, len(php_global_vars)):
            php_global_var = php_global_vars[i]
            if vuln_parameter:
                restrict += f'node.{NodeField.CODE}.contains("{php_global_var}[\\"{vuln_parameter}\\"]")'
            else:
                restrict += f'node.{NodeField.CODE}.contains("{php_global_var}")'
            if i != (len(php_global_vars) - 1):
                restrict += " || "
            else:
                restrict += "))"
        user_input_cpg_nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [],
            restricts = [restrict, f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})", f"{NodeMethod.MAP}(x=> (x.node.{NodeField.ID}, x.node.{NodeField.CODE}, x.node.{NodeField.LOCATION}.{NodeField.FILE_NAME}, x.node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}, x.node.{NodeField.METHOD_FULL_NAME}))", "take(26)"]
        )
        if user_input_cpg_nodes:
            for i in range(0, len(user_input_cpg_nodes)):
                if isinstance(user_input_cpg_nodes[i], dict):
                    user_input_cpg_nodes[i][NodeField.ID] = user_input_cpg_nodes[i]["_1"]
                    user_input_cpg_nodes[i][NodeField.CODE] = user_input_cpg_nodes[i]["_2"]
                    user_input_cpg_nodes[i][NodeField.FILE_NAME] = user_input_cpg_nodes[i]["_3"]
                    user_input_cpg_nodes[i][NodeField.LINE_NUMBER] = user_input_cpg_nodes[i]["_4"]
                    user_input_cpg_nodes[i][NodeField.METHOD_FULL_NAME] = user_input_cpg_nodes[i]["_5"]
                    del user_input_cpg_nodes[i]["_1"]
                    del user_input_cpg_nodes[i]["_2"]
                    del user_input_cpg_nodes[i]["_3"]
                    del user_input_cpg_nodes[i]["_4"]
                    del user_input_cpg_nodes[i]["_5"]
        return user_input_cpg_nodes

    def find_var_declaration_source_node(self, method_cpg_node: dict, variable_name: str, is_patched: bool):
        '''
        查找在方法内变量所在赋值语句的来源节点 (构造函数或实例化方法, 此函数专为分析XXE漏洞而实现)
        '''
        def have_target_variable_node(cpg_node: dict, variable_name: str):
            '''
            检查赋值语句的左值是否有目标变量节点
            '''
            if not isinstance(cpg_node, dict) or not variable_name:
                return False

            target_nodes: List[dict] = self.find_assign_targets(cpg_node)
            if isinstance(target_nodes, list):
                for node in target_nodes:
                    if isinstance(node, dict):
                        if node.get(NodeField.CODE, None) == variable_name:
                            return True
            
            return True

        restricts = []
        if not isinstance(method_cpg_node, dict):
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

        restricts.append(NodeField.AST)
        restricts.append(NodeConstraint.IS_CALL)
        restricts.append(f'{NodeMethod.FILTER}(node => node.{NodeField.METHOD_FULL_NAME} == {NodeOperator.ASSIGNMENT})') # 赋值语句约束条件

        # 构造变量名称约束条件
        var_name_constraint = f'{NodeMethod.FILTER}(node => node.{NodeField.CODE}.contains("{variable_name}=") || node.{NodeField.CODE}.contains("{variable_name} ="))'
        restricts.append(var_name_constraint)

        nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [],
            restricts = restricts
        )

        # 获取定义了目标变量的赋值语句节点
        assignment_node = None
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict) and NodeField.ID in node.keys():
                    if have_target_variable_node(node, variable_name):
                        assignment_node = node
                        break
        
        if not isinstance(assignment_node, dict):
            return None
        
        # 获取赋值语句的右值节点
        source_nodes = self.find_assign_sources(assignment_node)
        if isinstance(source_nodes, list):
            for source_node in source_nodes:
                if isinstance(source_node, dict) and NodeField.ID in source_node.keys():
                    if source_node.get(NodeField.NAME, None) == NodeOperator.ALLOC:
                        # 处理构造方法 E.g. new SAXBuilder()
                        type_full_name = source_node.get(NodeField.TYPE_FULL_NAME, None)
                        init_method_call_node = self.find_init_method_call_node(method_cpg_node, type_full_name, is_patched)
                        if isinstance(init_method_call_node, dict):
                            return init_method_call_node
                    else:
                        # 处理普通的实例化方法 E.g. newInstance()
                        if source_node.get(NodeField.LABEL, None) == NodeLabel.CALL:
                            return source_node

        return None

    def find_possible_sink_nodes(self, sink_short_names: list, vuln_parameter: str, filenames: list):
        '''
        在有参数的情况下查找程序中可能的 Sink 点
        '''
        restrict = f"{NodeMethod.FILTER}(node => (("
        for i in range(0, len(sink_short_names)):
            short_name = sink_short_names[i]
            if short_name:
                restrict += f'node.{NodeField.CODE}.contains("{short_name}")'
            if i != (len(sink_short_names) - 1):
                restrict += " || "
            else:
                restrict += ")"
                if vuln_parameter:
                    restrict += f' && node.{NodeField.CODE}.contains("{vuln_parameter}")'
                restrict += f' && (! node.{NodeField.CODE}.contains("<input "))'
                restrict += "))"
        temp_possible_sink_nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [],
            restricts = [restrict, f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})", f"{NodeMethod.MAP}(x=> (x.node.{NodeField.ID}, x.node.{NodeField.CODE}, x.node.{NodeField.LOCATION}.{NodeField.FILE_NAME}, x.node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}, x.node.{NodeField.METHOD_FULL_NAME}))", "take(26)"]
        )
        if temp_possible_sink_nodes:
            for i in range(0, len(temp_possible_sink_nodes)):
                if isinstance(temp_possible_sink_nodes[i], dict):
                    temp_possible_sink_nodes[i][NodeField.ID] = temp_possible_sink_nodes[i]["_1"]
                    temp_possible_sink_nodes[i][NodeField.CODE] = temp_possible_sink_nodes[i]["_2"]
                    temp_possible_sink_nodes[i][NodeField.FILE_NAME] = temp_possible_sink_nodes[i]["_3"]
                    temp_possible_sink_nodes[i][NodeField.LINE_NUMBER] = temp_possible_sink_nodes[i]["_4"]
                    temp_possible_sink_nodes[i][NodeField.METHOD_FULL_NAME] = temp_possible_sink_nodes[i]["_5"]
                    del temp_possible_sink_nodes[i]["_1"]
                    del temp_possible_sink_nodes[i]["_2"]
                    del temp_possible_sink_nodes[i]["_3"]
                    del temp_possible_sink_nodes[i]["_4"]
                    del temp_possible_sink_nodes[i]["_5"]
        possible_sink_nodes = list()
        if filenames:
            for node in temp_possible_sink_nodes:
                for filename in filenames:
                    if isinstance(node, dict) and node[NodeField.FILE_NAME].find(filename) != -1:
                        possible_sink_nodes.append(node)
        if possible_sink_nodes == []:
            possible_sink_nodes = copy.deepcopy(temp_possible_sink_nodes)
        return possible_sink_nodes