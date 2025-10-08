from typing import List

from joern_manager.location_processor import LocationProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeMethod, NodeLabel, NodeOperator

class DataFlowProcessor(LocationProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def find_dominate_nodes(self, cpg_type: str, cpg_node: dict, variable_name = None):
        '''
        查找主导节点
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        restricts = [NodeField.DOMINATES, f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})"]
        if variable_name is not None:
            restricts = [NodeField.DOMINATES, f'{NodeMethod.FILTER}(node => node.{NodeField.CODE}.contains("{variable_name}"))', f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})"]

        nodes = self.find_nodes(
            cpg_type = cpg_type,
            conditions = [f'node.{NodeField.ID}=={str(node_id)}'],
            restricts = restricts
        )

        dominate_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return dominate_nodes

    def _find_downstream_cpg_nodes(self, cpg_node: dict, downstream_cpg_nodes: list) -> bool:
        '''
        检查当前节点是否是下游节点之一
        '''
        if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys():
            for downstream_cpg_node in downstream_cpg_nodes:
                if isinstance(downstream_cpg_node, dict) and NodeField.ID in downstream_cpg_node.keys():
                    if str(cpg_node.get(NodeField.ID, None)) == str(downstream_cpg_node.get(NodeField.ID, None)):
                        return True
        return False

    def check_data_dependency(self, upstream_cpg_node: dict, downstream_cpg_nodes: list, upstram_id_dep_map: dict = None) -> bool:
        '''
        检查数据流依赖关系

        parameter
        --------
        upstream_cpg_nodes: 上游待分析的节点列表,其可能是变量/函数调用
        downstream_cpg_nodes: 下游待分析的节点列表
        upstram_id_dep_map: 上游已经处理了的CPG Nodes的节点ID和是否存在控制流依赖关系的映射关系 Dict[str, bool], value为None代表尚未分析完成
        '''
        # 添加key
        def add_key(map_key: str):
            if map_key is not None:
                if map_key not in upstram_id_dep_map.keys():
                    upstram_id_dep_map[map_key] = None

        # self.log_manager.log_info(f"Checking Data Dependency [Upstream : {self.get_cpg_info(upstream_cpg_node)}] [Downstream Number : {len(downstream_cpg_nodes)}]", False, self.indent_level + 1)
        if upstram_id_dep_map is None:
            upstram_id_dep_map = {}

        for downstream_cpg_node in downstream_cpg_nodes:
            up_down_key = self.generate_key(upstream_cpg_node, downstream_cpg_node)
            if up_down_key is None:
                continue
            add_key(up_down_key)

            # 如果下游是函数调用节点,就不必对齐进行分析
            if self.is_method_call(downstream_cpg_node):
                return False

            # 检查是否已经分析了下游->上游的依赖关系
            down_up_key = self.generate_key(downstream_cpg_node, upstream_cpg_node)
            if down_up_key in upstram_id_dep_map.keys():
                if isinstance(upstram_id_dep_map[down_up_key], bool) and upstram_id_dep_map[down_up_key]:
                    upstram_id_dep_map[up_down_key] = False

            if isinstance(upstram_id_dep_map[up_down_key], bool):
                # 若记录了映射关系,返回此前的结果,以避免重复分析
                if upstram_id_dep_map[up_down_key]:
                    return True
                continue

            # 若没有记录映射关系,则通过数据流分析记录并返回映射关系
            # self.log_manager.log_info(f"Analyzing [Downstream : {self.get_cpg_info(downstream_cpg_node)}]", False, self.indent_level + 2)
            if self.is_reachable(upstream_cpg_node, downstream_cpg_node):
                upstram_id_dep_map[up_down_key] = True # 记录映射关系
                # self.log_manager.log_info(f"Detect Data Dependency Between Nodes", False, self.indent_level + 2)
                return True
            else:
                upstram_id_dep_map[up_down_key] = False # 记录映射关系
        return False

    # ======================================== Reaching Def Start ========================================
    
    def find_reachingDefIn_nodes(self, cpg_node: dict):
        reachingDefIn_nodes = []
        if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys():
            node_id = cpg_node.get(NodeField.ID, None)
            nodes = self.find_nodes(
                cpg_type = NodeType.ALL,
                conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
                restricts = [NodeField.REACHING_DEF_IN]
            )
            for node in nodes:
                if isinstance(node, dict) and NodeField.LABEL in node.keys():
                    if node[NodeField.LABEL] not in [NodeLabel.METHOD, NodeLabel.METHOD_PARAMETER_OUT]:
                        reachingDefIn_nodes.append(node)
        return reachingDefIn_nodes
    
    def find_reachingDefOut_nodes(self, cpg_node: dict):
        reachingDefOut_nodes = []
        if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys():
            node_id = cpg_node.get(NodeField.ID, None)
            nodes = self.find_nodes(
                cpg_type = NodeType.ALL,
                conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
                restricts = [NodeField.REACHING_DEF_OUT]
            )
            for node in nodes:
                if isinstance(node, dict) and NodeField.LABEL in node.keys():
                    if node[NodeField.LABEL] not in [NodeLabel.METHOD, NodeLabel.METHOD_PARAMETER_OUT]:
                        reachingDefOut_nodes.append(node)
        return reachingDefOut_nodes
    
    def is_reachable(self, source_node: dict, sink_node: dict) -> bool:
        '''
        检查两个CPG节点是否存在数据流依赖关系
        '''
        # 构造变量定义语句
        def construct_define_var_statement(cpg_node: dict):
            node_id = None
            define_var = None
            if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys() and NodeField.LABEL in cpg_node.keys():
                node_id = cpg_node.get(NodeField.ID, None)
                if cpg_node[NodeField.LABEL] == NodeLabel.CALL:
                    define_var = f"cpg.{NodeType.CALL}.{NodeMethod.FILTER}(node=>node.{NodeField.ID}=={node_id})"
                elif cpg_node[NodeField.LABEL] == NodeLabel.IDENTIFIER:
                    define_var = f"cpg.{NodeType.IDENTIFIER}.{NodeMethod.FILTER}(node=>node.{NodeField.ID}=={node_id})"
            return node_id, define_var
        
        source_id, define_var1 = construct_define_var_statement(source_node)
        sink_id, define_var2 = construct_define_var_statement(sink_node)
        
        # 检查可达性
        exist_path = False
        find_invalid_label = False
        
        if define_var1 and define_var2:
            check_reachable_statement = f"{define_var2}.reachableByFlows({define_var1}).toJson"
            nodes = self.find_nodes(None, None, None, query_statement = check_reachable_statement)
            # 数据流分析中,Joern存在分析方向混乱问题,部分类型的节点不应出现在路径中
            invalid_labels = [NodeLabel.METHOD_PARAMETER_OUT]
            if isinstance(nodes, list):
                for item in nodes:
                    if exist_path or find_invalid_label:
                        break
                    if isinstance(item, dict):
                        find_source = False
                        find_sink = False
                        elements = item.get("elements", None)
                        if isinstance(elements, list):
                            for element in elements:
                                if isinstance(element, dict):
                                    cpg_id = element.get(NodeField.ID, None)
                                    cpg_label = element.get(NodeField.LABEL, None)
                                    # 判断是否已经找到source->sink的路径
                                    if str(cpg_id) == str(source_id):
                                        find_source = True
                                    elif str(cpg_id) == str(sink_id):
                                        find_sink = True
                                    # 如果已经找到了source和sink,就认为找到了数据流依赖路径
                                    if find_source and find_sink:
                                        exist_path = True
                                        break
                                    # 判断是否找到了无效节点
                                    if cpg_label in invalid_labels:
                                        find_invalid_label = True
                                        break
        if exist_path and not find_invalid_label:
            return True
        else:
            return False
    
    def get_reachingDefIn_data_nodes(self, cpg_node: dict) -> List[dict]:
        '''
        获取数据节点的数据来源节点
        '''
        nodes = []
        data_nodes = []
        cpg_id = cpg_node.get(NodeField.ID, None) if isinstance(cpg_node, dict) else None
        if cpg_id is None:
            return []

        query_stmts = []
        query_stmts.append(f"""val visited = new java.util.HashSet[Long]()""")
        query_stmts.append(f'cpg.{NodeType.ALL}.{NodeMethod.FILTER}(_.{NodeField.ID} == ' + str(cpg_id) + ').repeat(_.flatMap { node => if (!visited.' + NodeMethod.CONTAINS + '(node.' + NodeField.ID + ')) { visited.add(node.' + NodeField.ID + '); node.' + NodeField.REACHING_DEF_IN + ' } else Iterator.empty }' + f')(_.until(_.hasLabel("{NodeLabel.CALL}")))')
        nodes1 = self.query(query_stmts)
        if isinstance(nodes1, list):
            nodes.extend(nodes1)

        query_stmts = []
        query_stmts.append(f"""val visited = new java.util.HashSet[Long]()""")
        query_stmts.append(f'cpg.{NodeType.ALL}.{NodeMethod.FILTER}(_.{NodeField.ID} == ' + str(cpg_id) + ').repeat(_.flatMap { node => if (!visited.' + NodeMethod.CONTAINS + '(node.' + NodeField.ID + ')) { visited.add(node.' + NodeField.ID + '); node.' + NodeField.REACHING_DEF_IN + ' } else Iterator.empty }' + f')(_.until(_.hasLabel("{NodeLabel.IDENTIFIER}")))')
        nodes2 = self.query(query_stmts)
        if isinstance(nodes2, list):
            nodes.extend(nodes2)

        for node in nodes:
            if isinstance(node, dict):
                if node.get(NodeField.LABEL, None) == NodeLabel.CALL:
                    if node.get(NodeField.METHOD_FULL_NAME) == NodeOperator.FieldAccess:
                        data_nodes.append(node)
                elif node.get(NodeField.LABEL, None) == NodeLabel.IDENTIFIER:
                    if node.get(NodeField.CODE, None) != "this":
                        data_nodes.append(node)
        
        return data_nodes

    # ======================================== Reaching Def End ========================================