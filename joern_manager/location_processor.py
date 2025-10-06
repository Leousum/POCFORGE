from typing import List

from method_processor import MethodProcessor
from cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class LocationProcessor(MethodProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)
   
    def find_cpg_by_filename_linenum(self, file_name: str, line_num: any):
        '''
        根据文件名称和行号检索CPG节点
        '''
        nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f'node.{NodeField.LOCATION}.{NodeField.FILE_NAME}=="{str(file_name)}"', f"node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}==Some(value = {str(line_num)})"],
            restricts = []
        )
        # 筛选查询结果中的节点
        special_types = [NodeLabel.CALL, NodeLabel.IDENTIFIER]
        if nodes:
            for node in nodes:
                if isinstance(node, dict) and NodeField.LABEL in node.keys():
                    for special_type in special_types:
                        if node[NodeField.LABEL] == special_type:
                            return node
        return None

    def find_cpg_call_node_location(self, cpg_node: dict):
        '''
        查找 CPG 节点的位置信息
        '''
        if not isinstance(cpg_node, dict):
            return None

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [f"{NodeMethod.MAP}(x=>(x.node.{NodeField.LOCATION}.{NodeField.FILE_NAME}, x.node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}))"]
        )
        if nodes != []:
            return nodes[0]
        return None

    def find_cpg_call_node_location_by_id(self, cpg_id):
        '''
        根据 CPG Node 的 ID 属性查找 CPG 节点的位置信息
        '''
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f"node.{NodeField.ID}=={str(cpg_id)}"],
            restricts = [f"{NodeMethod.MAP}(x=>(x.node.{NodeField.LOCATION}.{NodeField.FILE_NAME}, x.node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}))"]
        )
        if nodes != []:
            return nodes[0]
        return None
    
    def find_cpg_call_nodes_by_line_num(self, file_path: str, line_num: int):
        '''
        根据行号在指定文件中查找所有CPG Nodes
        '''
        cpg_nodes: List[dict] = []
        if file_path is not None and line_num is not None:
            nodes = self.find_nodes(
                cpg_type = NodeType.CALL,
                conditions = [f'node.{NodeField.LOCATION}.{NodeField.FILE_NAME} == "{file_path}"', f'node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) == {line_num}'],
                restricts = []
            )
            if nodes == []:
                nodes = self.find_nodes(
                    cpg_type = NodeType.CALL,
                    conditions = [f'node.{NodeField.LOCATION}.{NodeField.FILE_NAME} == "{file_path}"', f'node.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) == {line_num}'],
                    restricts = []
                )
            cpg_nodes= [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return cpg_nodes
    
    def find_cpg_call_nodes_only_by_line_num(self, line_num: int):
        '''
        只根据行号查找所有CPG Nodes
        '''
        cpg_nodes: List[dict] = []
        if line_num is not None:
            nodes = self.find_nodes(
                cpg_type = NodeType.CALL,
                conditions = [f'node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}==Some(value={line_num})'],
                restricts = []
            )
            cpg_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return cpg_nodes

    def find_method_call_nodes_in_file(self, file_path: str, target_method_full_name: str):
        '''
        在所属文件中找到访问了指定方法签名的方法调用节点
        '''
        method_call_nodes = []
        if not target_method_full_name:
            return []

        conditions = [f'node.{NodeField.LOCATION}.{NodeField.FILE_NAME}=="{file_path}"', f'node.{NodeField.METHOD_FULL_NAME}=="{target_method_full_name}"']
        if target_method_full_name.find(":<unresolvedSignature>") != -1:
            package_class_name = target_method_full_name[:target_method_full_name.find(":<unresolvedSignature>")]
            conditions = [f'node.{NodeField.LOCATION}.{NodeField.FILE_NAME}=="{file_path}"', f'node.{NodeField.METHOD_FULL_NAME}.contains("{package_class_name}")']

        if file_path is not None and target_method_full_name is not None:
            nodes = self.find_nodes(
                cpg_type = NodeType.ALL,
                conditions = conditions,
                restricts = [f'{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})']
            )
            method_call_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return method_call_nodes

    def find_cpg_nodes_within_interval(self, file_path: str, method_full_name: str, start: int, end: int):
        '''
        查找行号在指定区间内的所有 Identifier和Field Access 两种类型的CPG Nodes
        '''
        cpg_nodes: List[dict] = []
        if method_full_name is not None and start is not None and end is not None:
            query_for_identifier = None
            query_for_field_access = None
            if start == end:
                query_for_identifier = f'cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node=>node.{NodeField.FULL_NAME}=="{method_full_name}").ast.{NodeConstraint.IS_IDENTIFIER}.{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0)=={start}).toJson'
                query_for_field_access = f'cpg.{NodeType.CALL}.{NodeMethod.FILTER}(node=>node.{NodeField.LOCATION}.{NodeField.FILE_NAME}=="{file_path}").{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0)=={start}).{NodeMethod.FILTER}(x=>x.{NodeField.METHOD_FULL_NAME}=="{NodeOperator.FieldAccess}").toJson'
            else:
                query_for_identifier = f'cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node=>node.{NodeField.FULL_NAME}=="{method_full_name}").ast.{NodeConstraint.IS_IDENTIFIER}.{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) >= {start}).{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) <= {end}).toJson'
                query_for_field_access = f'cpg.{NodeType.CALL}.{NodeMethod.FILTER}(node=>node.{NodeField.LOCATION}.{NodeField.FILE_NAME}=="{file_path}").{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) >= {start}).{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) <= {end}).{NodeMethod.FILTER}(x=>x.{NodeField.METHOD_FULL_NAME}=="{NodeOperator.FieldAccess}").toJson'

            identifier_nodes = self.find_nodes(None, None, None, query_for_identifier)
            field_access_nodes = self.find_nodes(None, None, None, query_for_field_access)
            for nodes in [identifier_nodes, field_access_nodes]:
                temp_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
                cpg_nodes.extend(temp_nodes)
        return cpg_nodes

    def find_cfg_node_by_contain(self, parameter: str, relative_path: str):
        '''
        根据限制查找joern解析后的CPG节点

        parameter: 查找的代码所包含的信息
        relative_path: 查找的代码节点所在的文件名
        '''
        conditions = list()
        if parameter is not None:
            conditions.append(f'node.{NodeField.CODE}.{NodeMethod.CONTAINS}("{parameter}")')
        if relative_path is not None:
            conditions.append(f'node.{NodeField.LOCATION}.{NodeField.FILE_NAME}=="{relative_path}"')
        
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = conditions,
            restricts = [f"{NodeMethod.SORT_BY}(node => node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER})", "take(26)"]
        )
        source_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return source_nodes

    def get_lineNumber(self, cpg_node: dict):
        lineNumber = None
        if NodeField.LINE_NUMBER in cpg_node.keys():
            lineNumber = int(str(cpg_node[NodeField.LINE_NUMBER]).replace("\\", "").replace("\"", "").replace("\'", ""))
        return lineNumber
    
    def query_used_vars_by_lineNumber(self, line_number):
        query_stmts = []
        query_stmts.append(f"""cpg.{NodeType.CALL}.{NodeField.LINE_NUMBER}({line_number}).out(Argument).{NodeConstraint.IS_IDENTIFIER}.{NodeMethod.MAP}(node => [node.code, node.{NodeField.LINE_NUMBER}]).l""")
        return self.query(query_stmts)