from base_server import BaseServer
from cpg_field import NodeType, NodeField, NodeMethod, NodeLabel

class ASTProcessor(BaseServer):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def find_astChildren(self, cpg_node: dict):
        '''
        查找 AST 子节点
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.AST_CHILDREN]
        )

        ast_children_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return ast_children_nodes
    
    def find_astParent(self, cpg_node: dict):
        '''
        查找 AST 父节点
        '''
        if not isinstance(cpg_node, dict):
            return []

        # 部分节点没有 AST 父节点,因此可以将其直接返回
        if NodeField.LABEL in cpg_node.keys():
            if cpg_node[NodeField.LABEL] in [NodeLabel.CONTROL_STRUCTURE, NodeLabel.RETURN, NodeLabel.METHOD, NodeLabel.TYPE_DECL]:
                return [cpg_node]

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.AST_IN]
        )

        ast_parent_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return ast_parent_nodes

    def find_astParent_until_top(self, cpg_node: dict, processed_ids: list = None):
        '''
        查找 AST 顶层节点
        '''
        if processed_ids is None:
            processed_ids = []

        # 找到最上层的AST父节点(可能是CALL、CONTROL_STRUCTURE、RETURN三种类型)
        if isinstance(cpg_node, dict) and NodeField.LABEL in cpg_node.keys() and NodeField.ID in cpg_node.keys():
            # 递归出口: 当发现CPG Node被重复分析时,及时结束递归
            node_id = cpg_node.get(NodeField.ID, None)
            if str(node_id) in processed_ids:
                return None

            processed_ids.append(str(node_id))
            if cpg_node[NodeField.LABEL] == NodeLabel.RETURN:
                return cpg_node
            else:
                ast_parent_nodes = self.find_astParent(cpg_node)
                if ast_parent_nodes == []:
                    control_node = self.get_control_node(cpg_node)
                    if control_node is not None:
                        return control_node
                    else:
                        return cpg_node
                elif ast_parent_nodes[0][NodeField.LABEL] == NodeLabel.BLOCK:
                    return cpg_node
                else:
                    if ast_parent_nodes[0] is not None:
                        result_cpg_node = self.find_astParent_until_top(ast_parent_nodes[0], processed_ids)
                        if isinstance(result_cpg_node, dict):
                            return result_cpg_node
                    else:
                        return cpg_node
        return None

    def find_astParent_until_call_or_control(self, cpg_node: dict, processed_ids: list = None):
        '''
        递归找到CPG Node的上层第一个CALL/CONTROL_STRUCTURE/MEMBER类型的AST节点
        '''
        if processed_ids is None:
            processed_ids = []

        if isinstance(cpg_node, dict) and NodeField.LABEL in cpg_node.keys() and NodeField.ID in cpg_node.keys():
            # 递归出口: 当发现CPG Node被重复分析时,及时结束递归
            if str(cpg_node[NodeField.ID]) in processed_ids:
                return None
            processed_ids.append(str(cpg_node[NodeField.ID]))
            if cpg_node[NodeField.LABEL] in [NodeLabel.CALL, NodeLabel.CONTROL_STRUCTURE, NodeLabel.TYPE_DECL, NodeLabel.METHOD, NodeLabel.MEMBER]:
                return cpg_node
            else:
                ast_parent_nodes = self.find_astParent(cpg_node)
                for ast_parent_node in ast_parent_nodes:
                    result_cpg_node = self.find_astParent_until_call_or_control(ast_parent_node, processed_ids)
                    if isinstance(result_cpg_node, dict):
                        return result_cpg_node
        return None

    def get_control_node(self, cpg_node: dict):
        '''
        查找控制结构对应的节点 (在不能根据astParent获得控制节点时使用此方法)
        '''
        if not isinstance(cpg_node, dict):
            return None

        # 首先检查该节点是否是控制结构
        if cpg_node.get(NodeField.LABEL, None) == NodeLabel.CONTROL_STRUCTURE:
            return cpg_node

        # 方法一: 根据行号进行查找
        lineNumber = self.get_lineNumber(cpg_node)
        if lineNumber is not None:
            nodes1 = self.find_nodes(
                cpg_type = NodeType.CONTROL_STRUCTURE,
                conditions = [],
                restricts = [f"{NodeMethod.FILTER}(_.{NodeField.LINE_NUMBER}==Some(value = {str(lineNumber)}))"]
            )
            if isinstance(nodes1, list):
                for node1 in nodes1:
                    if isinstance(node1, dict):
                        return node1

        # 方法二: 根据代码
        code = cpg_node.get(NodeField.CODE, None)
        if code:
            nodes2 = self.find_nodes(
                cpg_type = NodeType.CONTROL_STRUCTURE,
                conditions = [],
                restricts = [f'{NodeMethod.FILTER}(_.{NodeField.CODE}.{NodeMethod.CONTAINS}("{code}"))']
            )
            control_node = None
            if nodes2:
                # 查找node id相距最小的节点
                node_id = int(cpg_node.get(NodeField.ID, None))
                min_distance = 1000
                for node in nodes2:
                    if isinstance(node, dict):
                        distance = abs(int(node.get(NodeField.ID, None)) - node_id)
                        if distance <= min_distance:
                            control_node = node
                            min_distance = distance
                return control_node
        return None