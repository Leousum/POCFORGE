import copy
from typing import List

from joern_manager.method_base_processor import MethodBaseProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class MethodReturnProcessor(MethodBaseProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)
    
    def get_method_return_type(self, cpg_node: dict):
        '''
        获取函数的返回值类型
        '''
        method_full_name = self.get_method_full_name(cpg_node)
        method_return_nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
            restricts = [NodeType.METHOD_RETURN]
        )
        if method_return_nodes:
            method_return_node = method_return_nodes[0]
            if isinstance(method_return_node, dict):
                return method_return_node.get(NodeField.TYPE_FULL_NAME, "ANY")
        return "ANY"

    def get_method_return_data_nodes(self, method_full_name: str):
        # 获取函数返回的数据节点
        data_nodes = []
        if method_full_name:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
                restricts = [NodeType.METHOD_RETURN, NodeField.CFG_IN, NodeField.CFG_IN]
            )
            for node in nodes:
                if isinstance(node, dict):
                    data_nodes.append(node)
        return data_nodes

    def get_method_return_nodes(self, method_full_name: str):
        # 获取函数返回语句
        data_nodes = []
        if method_full_name:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
                restricts = [NodeType.METHOD_RETURN, NodeField.CFG_IN]
            )
            for node in nodes:
                if isinstance(node, dict):
                    data_nodes.append(node)
        return data_nodes

    def is_related_to_method_return(self, cpg_node: dict) -> bool:
        '''
        检查CPG Node是否与函数返回值有关
        '''
        if not isinstance(cpg_node, dict):
            return False
        
        # (1) 如果节点本身就处于返回值节点中,那么就不用再查询了
        if cpg_node.get(NodeField.LABEL, None) in [NodeLabel.RETURN, NodeLabel.METHOD_RETURN]:
            return True

        # (2) 做一次迭代查询,直至找到返回值节点
        cpg_id = cpg_node.get(NodeField.ID, None) if isinstance(cpg_node, dict) else None
        if cpg_id is None:
            return False
        query_stmts = []
        query_stmts.append(f"""val visited = new java.util.HashSet[Long]()""")
        query_stmts.append(f'cpg.all.{NodeMethod.FILTER}(_.{NodeField.ID} == ' + str(cpg_id) + ').repeat(_.flatMap { node => if (!visited.contains(node.' + NodeField.ID + ')) { visited.add(node.' + NodeField.ID + '); node._reachingDefOut } else Iterator.empty })(_.until(_.hasLabel("RETURN"))).dedup.take(1)')
        nodes = self.query(query_stmts)
        if isinstance(nodes, list) and nodes:
            return True

        # (3) 如果方法返回值是布尔类型,那么将难以根据数据流关系找到返回值节点,此时要检查函数签名
        belong_method_node = self.find_belong_method(cpg_node)
        if isinstance(belong_method_node, dict) and str(belong_method_node.get(NodeField.FULL_NAME, None)).find(":boolean(") != -1:
            return True

        return False