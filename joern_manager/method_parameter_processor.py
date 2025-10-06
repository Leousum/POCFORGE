import copy
from typing import List

from joern_manager.class_processor import ClassProcessor
from cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class MethodParameterProcessor(ClassProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)
    
    def find_method_parameters(self, cpg_node: dict):
        # 查找函数调用对应的函数定义时的形参列表
        parameter_nodes = []
        nodes = []
        if isinstance(cpg_node, dict):
            cpg_label = cpg_node.get(NodeField.LABEL, None)
            
            if cpg_label == NodeLabel.METHOD:
                method_id = cpg_node.get(NodeField.ID, None)
                if method_id:
                    nodes = self.find_nodes(
                        cpg_type = NodeType.METHOD,
                        conditions = [f'node.{NodeField.ID}=={method_id}'],
                        restricts = [NodeField.PARAMETER]
                    )
            if nodes == []:
                method_full_name = cpg_node.get(NodeField.METHOD_FULL_NAME, None) if cpg_node.get(NodeField.METHOD_FULL_NAME, None) else cpg_node.get(NodeField.FULL_NAME, None)
                if method_full_name:
                    method_full_name = method_full_name.replace(".<returnValue>", "")
                    nodes = self.find_nodes(
                        cpg_type = NodeType.METHOD,
                        conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
                        restricts = [NodeField.PARAMETER]
                    )
            for node in nodes:
                if isinstance(node, dict):
                    parameter_nodes.append(node)

        # 检查是否缺失了 this 关键字所在的CPG Node
        missing_parameter_node = self.fill_missing_parameter(cpg_node, parameter_nodes)
        if isinstance(missing_parameter_node, dict):
            parameter_nodes.append(missing_parameter_node)
            parameter_nodes = sorted(parameter_nodes, key=lambda x: x.get(NodeField.INDEX, float('inf')))
        return parameter_nodes
    
    def fill_missing_parameter(self, method_node: dict, parameter_nodes: List[dict]):
        '''
        补全缺失的形参节点 (专门服务于`find_method_parameters`函数)
        '''
        # [Joern Issues #1]: 2025-06-20发现Joern通过parameter查找Java的方法定义的形参列表时, 会缺失部分this关键字节点, 严重影响静态分析流程!
        def is_missing_this(parameter_nodes: List[dict]) -> bool:
            '''
            判断是否缺失了this关键字
            '''
            if not parameter_nodes or not isinstance(parameter_nodes, list):
                return False

            for parameter_node in parameter_nodes:
                if isinstance(parameter_node, dict):
                    if parameter_node.get(NodeField.NAME, None) == "this" or parameter_node.get(NodeField.CODE, None) == "this":
                        return False

            return True

        if not isinstance(method_node, dict):
            return None

        if is_missing_this(parameter_nodes):
            # 查找所属类节点
            method_line_num = method_node.get(NodeField.LINE_NUMBER, None)
            class_cpg_node = self.find_belong_class(method_node)
            class_cpg_id = None
            if isinstance(class_cpg_node, dict):
                class_cpg_id = class_cpg_node.get(NodeField.ID, None)
            if class_cpg_id is None:
                return None

            # 查找this关键字节点
            nodes = self.find_nodes(
                cpg_type = NodeType.TYPE_DECL,
                conditions = [f'node.{NodeField.ID}=={class_cpg_id}'],
                restricts = [NodeField.AST, NodeConstraint.IS_IDENTIFIER,f'{NodeMethod.FILTER}(node=>node.{NodeField.NAME}=="this")', 'take(3)']
            )
            for node in nodes:
                if isinstance(node, dict):
                    node[NodeField.LINE_NUMBER] = method_line_num # 此处复制行号
                    node[NodeField.INDEX] = 0 # 注意: 此处必须为0
                    return node

            # 当未找到可以补充的this节点时,就人工构造相应的节点
            this_node = {
                NodeField.ID: 11111, # 随便给的id
                NodeField.DYNAMIC_TYPE_HINT_FULL_NAME:[],
                NodeField.NAME: "this",
                NodeField.CODE: "this",
                NodeField.TYPE_FULL_NAME: class_cpg_node.get(NodeField.FULL_NAME, None),
                NodeField.LABEL: NodeLabel.IDENTIFIER,
                NodeField.LINE_NUMBER: method_line_num,
                NodeField.INDEX: 0 # 注意: 此处必须为0
            }
            return this_node
        return None

    def get_param_types(self, method_node: dict):
        '''
        获取函数形参列表
        '''
        param_types = []
        method_full_name = method_node.get(NodeField.METHOD_FULL_NAME, None) if method_node.get(NodeField.METHOD_FULL_NAME, None) else method_node.get(NodeField.FULL_NAME, None)
        if method_full_name:
            if method_full_name.find("(") != -1 and method_full_name.find(")") != -1:
                param_str: str = method_full_name[method_full_name.find("(") + 1:method_full_name.find(")")]
                if param_str.find(", ") != -1:
                    param_types = param_str.split(", ")
                else:
                    param_types = param_str.split(",")
        return param_types
    
    def get_parameter_types(self, method_node: dict):
        '''
        获取函数形参类型列表(包含调用者本身的类型)
        '''
        parameter_types = []
        if isinstance(method_node, dict):
            parameter_nodes = self.find_method_parameters(method_node)
            for parameter_node in parameter_nodes:
                if isinstance(parameter_node, dict) and NodeField.TYPE_FULL_NAME in parameter_node.keys():
                    if parameter_node[NodeField.TYPE_FULL_NAME]:
                        parameter_types.append(parameter_node[NodeField.TYPE_FULL_NAME])
        return parameter_types
    
    def get_reachingDefIn_parameter_nodes(self, cpg_node: dict) -> List[dict]:
        '''
        获取数据节点对应的形参节点
        '''
        cpg_id = cpg_node.get(NodeField.ID, None) if isinstance(cpg_node, dict) else None
        if cpg_id is None:
            return []

        query_stmts = []
        parameter_nodes = []
        query_stmts.append(f"""val visited = new java.util.HashSet[Long]()""")
        query_stmts.append(f'cpg.{NodeType.ALL}.{NodeMethod.FILTER}(_.{NodeField.ID} == ' + str(cpg_id) + ').repeat(_.flatMap { node => if (!visited.' + NodeMethod.CONTAINS + '(node.' + NodeField.ID + ')) { visited.add(node.' + NodeField.ID + '); node.' + NodeField.REACHING_DEF_IN + ' } else Iterator.empty })' + f'(_.until(_.hasLabel("{NodeLabel.METHOD_PARAMETER_IN}")))')
        nodes = self.query(query_stmts)

        if isinstance(nodes, list) and nodes:
            for node in nodes:
                if isinstance(node, dict):
                    parameter_nodes.append(node)
        return parameter_nodes

    def get_same_types_between_method_and_argument(self, method_node: dict, argument_types: list):
        '''
        获取与实参类型数量一致的形参数量(帮助挑选方法体节点)
        '''
        parameter_types = self.get_parameter_types(method_node)
        return [parameter_type for parameter_type in parameter_types if parameter_type in argument_types]

    def is_related_to_method_parameter(self, cpg_node: dict) -> bool:
        '''
        检查CPG Node是否与函数形参有关
        '''
        if not isinstance(cpg_node, dict):
            return None, False
        
        # (1) 如果节点本身就是形参中,那么就不用再查询了
        if cpg_node.get(NodeField.LABEL, None) in [NodeLabel.METHOD_PARAMETER_IN]:
            return None, True

        # (2) 做一次迭代查询,直至找到形参节点
        cpg_id = cpg_node.get(NodeField.ID, None) if isinstance(cpg_node, dict) else None
        if cpg_id is None:
            return None, False

        query_stmts = []
        query_stmts.append(f"""val visited = new java.util.HashSet[Long]()""")
        query_stmts.append(f'cpg.{NodeType.ALL}.{NodeMethod.FILTER}(_.{NodeField.ID} == ' + str(cpg_id) + ').repeat(_.flatMap { node => if (!visited.' + NodeMethod.CONTAINS + '(node.' + NodeField.ID + ')) { visited.add(node.' + NodeField.ID + '); node.' + NodeField.REACHING_DEF_IN + ' } else Iterator.empty })' + f'(_.until(_.hasLabel("{NodeLabel.METHOD_PARAMETER_IN}"))).dedup.take(1)')
        nodes = self.query(query_stmts)
        if isinstance(nodes, list) and nodes:
            for node in nodes:
                if isinstance(node, dict) and node.get(NodeField.INDEX, None) is not None:
                    return node.get(NodeField.INDEX, None), True
            
            return None, True

        return None, False