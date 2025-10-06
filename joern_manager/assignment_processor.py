from typing import List

from cfg_processor import CFGProcessor
from cpg_field import NodeType, NodeField

class AssignmentProcessor(CFGProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def find_assign_targets(self, cpg_node: dict):
        '''
        查找赋值语句的左值节点列表
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f"node.{NodeField.ID} == {str(node_id)}"],
            restricts = [NodeType.ASSIGNMENT, NodeField.TARGET]
        )

        target_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return target_nodes

    def find_assign_sources(self, cpg_node: dict):
        '''
        查找赋值语句的右值节点列表
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeType.ASSIGNMENT, NodeField.SOURCE]
        )

        source_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return source_nodes

    def find_assign_final_sources(self, cpg_node: dict):
        '''
        返回赋值语句最右边的数据.e.g.String name1 = name2 = name3 = "test"; 返回"test"
        '''
        source_nodes = self.find_assign_sources(cpg_node)
        if source_nodes:
            return source_nodes[-1]
        else:
            return None