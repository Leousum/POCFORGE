import copy
from typing import List

from joern_manager.method_call_processor import MethodCallProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class MethodArgumentProcessor(MethodCallProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def fill_missing_argument(self, method_call_node: dict, argument_nodes: List[dict]):
        '''
        补全缺失的实参节点 (专门服务于`find_method_call_arguments`函数)
        '''
        # [Joern Issues #2]: 2025-06-21发现Joern通过argument查找Java的方法定义的实参列表时, 会缺失部分zero节点, 严重影响静态分析流程!
        def is_missing_zero_node(argument_nodes: List[dict]) -> bool:
            '''
            判断是否缺失了zero节点
            '''
            if not argument_nodes or not isinstance(argument_nodes, list):
                return False

            if isinstance(argument_nodes, list):
                for node in argument_nodes:
                    if isinstance(node, dict) and node.get(NodeField.ARGUMENT_INDEX, None) == 0:
                        return False
            return True

        if not isinstance(method_call_node, dict):
            return None

        if is_missing_zero_node(argument_nodes):
            # 查找所属类节点
            method_call_line_num = method_call_node.get(NodeField.LINE_NUMBER, None)
            class_cpg_node = self.find_belong_class(method_call_node)
            class_cpg_id = None
            if isinstance(class_cpg_node, dict):
                class_cpg_id = class_cpg_node.get(NodeField.ID, None)
            if class_cpg_id is None:
                return None

            # 查找this节点
            nodes = self.find_nodes(
                cpg_type = NodeType.TYPE_DECL,
                conditions = [f'node.{NodeField.ID}=={class_cpg_id}'],
                restricts = [NodeField.AST, NodeConstraint.IS_IDENTIFIER, f'{NodeMethod.FILTER}(node=>node.{NodeField.NAME}=="this")', 'take(3)']
            )
            for node in nodes:
                if isinstance(node, dict):
                    node[NodeField.LINE_NUMBER] = method_call_line_num # 此处复制行号
                    node[NodeField.ARGUMENT_INDEX] = 0 # 注意: 此处必须为0
                    return node

            # 当未找到可以补充的this节点时,就人工构造相应的节点
            zero_node = {
                NodeField.ID: 11111, # 随便给的id
                NodeField.DYNAMIC_TYPE_HINT_FULL_NAME:[],
                NodeField.NAME: "zero",
                NodeField.CODE: "zero",
                NodeField.TYPE_FULL_NAME: class_cpg_node.get(NodeField.FULL_NAME, None),
                NodeField.LABEL: NodeLabel.IDENTIFIER,
                NodeField.LINE_NUMBER: method_call_line_num,
                NodeField.ARGUMENT_INDEX: 0 # 注意: 此处必须为0
            }
            return zero_node
        return None

    def find_method_call_arguments(self, cpg_info: any):
        '''
        查找函数调用的实参列表
        '''
        argument_nodes = []
        node_id = None
        cpg_node = None
        if isinstance(cpg_info, str) or isinstance(cpg_info, int):
            node_id = cpg_info
            cpg_node = self.find_cpg_node_by_id(node_id)
        elif isinstance(cpg_info, dict):
            node_id = cpg_info.get(NodeField.ID, None)
            cpg_node = cpg_info
        if node_id is not None:
            nodes = self.find_nodes(
                cpg_type = NodeType.CALL,
                conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
                restricts = [NodeField.ARGUMENT]
            )
            argument_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []

        # 检查是否缺失了argumentIndex为0的CPG Node
        missing_argument_node = self.fill_missing_argument(cpg_node, argument_nodes)
        if isinstance(missing_argument_node, dict):
            argument_nodes.append(missing_argument_node)
            argument_nodes = sorted(argument_nodes, key=lambda x: x.get(NodeField.ARGUMENT_INDEX, float('inf')))
        return argument_nodes
    
    def get_argument_types(self, call_node: dict):
        '''
        获取函数调用节点的实参类型列表(包含调用者本身的类型)
        '''
        argument_types = []
        if isinstance(call_node, dict):
            argument_nodes = self.find_method_call_arguments(call_node)
            for argument_node in argument_nodes:
                if isinstance(argument_node, dict) and NodeField.TYPE_FULL_NAME in argument_node.keys():
                    if argument_node[NodeField.TYPE_FULL_NAME]:
                        argument_types.append(argument_node[NodeField.TYPE_FULL_NAME])
        return argument_types