from typing import List

from joern_manager.assignment_processor import AssignmentProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeOperator

class ArrayProcessor(AssignmentProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def get_array_init_nodes_with_size(self, method_cpg_node: dict) -> List[dict]:
        '''
        获取指定了数组长度的数组初始化语句
        '''
        array_init_nodes = []

        if not isinstance(method_cpg_node, dict):
            return [], False
        
        method_id = method_cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [f'node.{NodeField.ID} == {method_id}'],
            restricts = [NodeField.AST, NodeConstraint.IS_CALL, f'{NodeMethod.FILTER}(node => node.{NodeField.METHOD_FULL_NAME} == {NodeOperator.ALLOC} && node.{NodeField.CODE}.{NodeMethod.CONTAINS}("[") && node.{NodeField.CODE}.{NodeMethod.CONTAINS}("]") && ! node.{NodeField.CODE}.{NodeMethod.CONTAINS}("[]"))', NodeMethod.DEDUP]
        )
        array_init_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return array_init_nodes