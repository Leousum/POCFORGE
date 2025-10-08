import copy

from joern_manager.ast_processor import ASTProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel

class CFGProcessor(ASTProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def find_cfgIn(self, cpg_node: dict):
        '''
        查找 CFG 父节点
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        cfg_in_nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.CFG_IN]
        )
        return cfg_in_nodes

    def find_cfgOut(self, cpg_node: dict):
        '''
        查找 CFG 子节点
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        cfg_out_nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.CFG_OUT]
        )
        return cfg_out_nodes

    def find_cfgNext_until_call(self, cpg_node: dict):
        '''
        迭代查找 CFG 子节点直至找到 _label 属性为 CALL 的节点
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [f"{NodeMethod.REPEAT}(_.{NodeField.CFG_NEXT})(_.{NodeMethod.UNTIL}(_.{NodeConstraint.IS_CALL}))"]
        )
        cfg_next_nodes = self.remove_duplicate_nodes(nodes)
        return cfg_next_nodes

    def find_controlledBy_nodes(self, cpg_node: dict):
        '''
        找到控制当前节点的节点
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.CONTROLLED_BY]
        )
        controlledBy_nodes: list = []
        for node in nodes:
            if isinstance(node, dict) and NodeField.ID in node.keys():
                controlledBy_nodes.append(node)
        return controlledBy_nodes

    def find_control_condition(self, cpg_node: dict):
        '''
        找到控制结构的条件
        '''
        if not isinstance(cpg_node, dict):
            return None

        node_id = cpg_node.get(NodeField.ID, None)
        condition_nodes = self.find_nodes(
            cpg_type = NodeType.CONTROL_STRUCTURE,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.CONDITION]
        )
        if condition_nodes:
            for node in condition_nodes:
                if isinstance(node, dict):
                    return node
        return None

    def find_control_condition_nodes_between_nodes(self, before_cpg_node: dict, after_cpg_node: dict):
        '''
        查找位于两个节点之间的控制流条件语句
        '''
        condition_nodes = list()
        if isinstance(before_cpg_node, dict) and isinstance(after_cpg_node, dict):
            call_node = self.find_astParent_until_call_or_control(after_cpg_node)
            if isinstance(call_node, dict):
                after_id = call_node.get(NodeField.ID, None)
                before_id = before_cpg_node.get(NodeField.ID, None)
                nodes = self.find_nodes(
                    cpg_type = NodeType.CALL,
                    conditions = [f"node.{NodeField.ID}=={str(after_id)}"],
                    restricts = [NodeField.CONTROLLED_BY, f"{NodeMethod.FILTER}(node => node.{NodeField.ID}>{str(before_id)})"]
                )
                condition_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return condition_nodes

    def find_switch_case(self, cpg_node: dict):
        # 获取Switch语句各个Case
        # 注意:返回的有一个节点是Switch语句的default分支节点
        nodes = list()
        jump_target_nodes = self.find_cfgOut(cpg_node)
        for jump_target_node in jump_target_nodes:
            if jump_target_node[NodeField.LABEL] == NodeLabel.JUMP_TARGET:
                if jump_target_node[NodeField.NAME] == "case":
                    case_nodes = self.find_cfgOut(jump_target_node)
                    if case_nodes:
                        nodes.append(case_nodes[0])
                elif jump_target_node[NodeField.NAME] == "default":
                    nodes.append(jump_target_node)
        return nodes
    
    def find_for_parts(self, cpg_node: dict):
        '''
        查找for循环的初始化、条件和更新3个部分对应的CPG Nodes
        '''
        node_id = cpg_node.get(NodeField.ID, None)
        target_nodes = self.find_nodes(
            cpg_type = NodeType.CONTROL_STRUCTURE,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.AST_CHILDREN, NodeConstraint.IS_CALL]
        )
        return target_nodes

    def is_control_structure(self, cpg_node: dict):
        '''
        判断一个节点是否是控制节点
        '''
        cfg_out_call_nodes = self.find_cfgOut_until_call(cpg_node, True)
        if cfg_out_call_nodes:
            cfg_out_call_node = cfg_out_call_nodes[0]
            controlledBy_nodes = self.find_controlledBy_nodes(cfg_out_call_node)
            if controlledBy_nodes:
                for controlledBy_node in controlledBy_nodes:
                    if isinstance(controlledBy_node, dict) and isinstance(cpg_node, dict):
                        if NodeField.ID in controlledBy_node.keys() and NodeField.ID in cpg_node.keys():
                            if controlledBy_node[NodeField.ID] == cpg_node[NodeField.ID]:
                                return True
        return False

    def find_cfgOut_until_call(self, cpg_node: dict, is_control_node: bool):
        '''
        查找 CFG 子节点直至找到 _label 属性为 CALL 的节点
        '''
        # 注意:控制结构,例如IF,SWITCH语句也被视为调用语句
        # is_control_node为True时,表示该节点是控制结构,要找后续的调用节点
        nodes = list()
        cfg_out_nodes = self.find_cfgOut(cpg_node)
        # 当一个节点的CFG后继节点有多个时,这个节点有可能是一个控制结构节点
        if not is_control_node:
            if len(cfg_out_nodes) > 1:
                if self.is_control_structure(cpg_node):
                    return [cpg_node]

        for node in cfg_out_nodes:
            if node[NodeField.LABEL] != NodeLabel.CALL:
                if node[NodeField.LABEL] == NodeLabel.RETURN:
                    nodes.append(node)
                else:
                    nodes.extend(self.find_cfgOut_until_call(node, False))
            else:
                nodes.append(node)

        call_nodes = self.remove_duplicate_nodes(nodes)
        return call_nodes

    def find_cfg_successors(self, cpg_node: dict):
        '''
        查找到 CFG 后继节点
        '''
        successors = list()
        if isinstance(cpg_node, dict):
            new_cpg_node = copy.deepcopy(cpg_node)
            is_control_node = False
            if cpg_node[NodeField.LABEL] == NodeLabel.CONTROL_STRUCTURE:
                is_control_node = True
                new_cpg_node = self.find_control_condition(cpg_node)

            nodes = list()
            if new_cpg_node is not None:
                cfg_out_call_nodes = self.find_cfgOut_until_call(new_cpg_node, is_control_node)
                for node in cfg_out_call_nodes:
                    top_ast_node = self.find_astParent_until_top(node)
                    if isinstance(top_ast_node, dict):
                        nodes.append(top_ast_node)

            successors = self.remove_duplicate_nodes(nodes)
            cpg_ids = list()
            for successor in successors:
                cpg_ids.append(str(successor.get(NodeField.ID, None)))
            self.log_manager.log_info(f"Find [{cpg_node['id']} {cpg_node['code']}] {len(successors)} successors: [{','.join(cpg_ids)}]", False, self.indent_level)
        return successors
    
    def generate_key(self, upstream_cpg_node: dict, downstream_cpg_node: dict):
        '''
        生成记录两个CPG Node之间映射关系的key : id1->id2
        '''
        def get_id(cpg_node: dict):
            if isinstance(cpg_node, dict):
                node_id = cpg_node.get(NodeField.ID, None)
                if isinstance(node_id, int):
                    return node_id
                elif isinstance(node_id, str) and node_id.isdigit():
                    return node_id
            return None

        id1 = get_id(upstream_cpg_node)
        id2 = get_id(downstream_cpg_node)
        if id1 is not None and id2 is not None:
            return f"{id1}=>{id2}"
        return None

    def check_dominate_node(self, branch_node: dict, source_node: dict):
        '''
        通过dominates方法检查source_node是否处于branch_node所在分支
        '''
        if isinstance(branch_node, dict) and isinstance(source_node, dict):
            branch_id = str(branch_node.get(NodeField.ID, None))
            source_id = str(source_node.get(NodeField.ID, None))
            if branch_id == source_id:
                return True

            nodes = self.find_nodes(
                cpg_type = NodeType.CALL,
                conditions = [f"node.{NodeField.ID}=={branch_id}"],
                restricts = [NodeField.DOMINATES, NodeConstraint.IS_CALL, f"{NodeMethod.FILTER}(node => node.{NodeField.ID}=={source_id})"] # TODO: f"{NodeMethod.MAP}(x=> (x.node.{NodeField.ID}, x.node.{NodeField.ID}))"
            )
            for node in nodes:
                if isinstance(node, dict):
                    if node.get(NodeField.ID, None) == source_id:
                        return True
        return False

    def check_control_dependency(self, upstream_cpg_node: dict, downstream_cpg_nodes: list, upstram_id_dep_map: dict = None) -> bool:
        '''
        检查控制流依赖关系

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

        # self.log_manager.log_info(f"Checking Control Dependency [Upstream : {self.get_cpg_info(upstream_cpg_node)}] [Downstream Number : {len(downstream_cpg_nodes)}]", False, self.indent_level + 1)
        if upstram_id_dep_map is None:
            upstram_id_dep_map = {}

        ast_top_cpg_node: dict = None

        # 如果是控制结构语句,则分析其条件语句控制的语句有哪些,从而确定控制流依赖关系
        # TODO: 未来考虑要不要分析数据流依赖导致的控制流依赖关系
        for downstream_cpg_node in downstream_cpg_nodes:
            up_down_key = self.generate_key(upstream_cpg_node, downstream_cpg_node)
            if up_down_key is None:
                continue
            add_key(up_down_key)

            # 检查是否已经分析了下游->上游的依赖关系
            down_up_key = self.generate_key(downstream_cpg_node, upstream_cpg_node)
            if down_up_key in upstram_id_dep_map.keys():
                if isinstance(upstram_id_dep_map[down_up_key], bool) and upstram_id_dep_map[down_up_key]:
                    upstram_id_dep_map[up_down_key] = False # 记录映射关系

            if isinstance(upstram_id_dep_map[up_down_key], bool):
                # 若记录了映射关系,返回此前的结果,以避免重复分析
                if upstram_id_dep_map[up_down_key]:
                    return True
                continue

            if ast_top_cpg_node is None:
                ast_top_cpg_node = self.find_astParent_until_top(upstream_cpg_node) # 获取AST最顶层节点
                if not isinstance(ast_top_cpg_node, dict) or ast_top_cpg_node.get(NodeField.LABEL, None) != NodeLabel.CONTROL_STRUCTURE:
                    upstram_id_dep_map[up_down_key] = False # 记录映射关系
                    return False

            top_down_key = self.generate_key(ast_top_cpg_node, downstream_cpg_node)
            if top_down_key is None:
                continue
            add_key(top_down_key)

            # 检查是否已经分析了下游->top点的依赖关系
            down_top_key = self.generate_key(downstream_cpg_node, ast_top_cpg_node)
            if down_top_key in upstram_id_dep_map.keys():
                if isinstance(upstram_id_dep_map[down_top_key], bool) and upstram_id_dep_map[down_top_key]:
                    upstram_id_dep_map[up_down_key] = False # 记录映射关系
                    upstram_id_dep_map[top_down_key] = False # 记录映射关系

            if isinstance(upstram_id_dep_map[top_down_key], bool):
                # 若记录了映射关系,返回此前的结果,以避免重复分析
                if upstram_id_dep_map[top_down_key]:
                    upstram_id_dep_map[up_down_key] = True # 记录映射关系
                    return True
                continue
            
            # self.log_manager.log_info(f"Analyzing [Downstream : {self.get_cpg_info(downstream_cpg_node)}]", False, self.indent_level + 2)
            downstream_ast_top_cpg_node: dict = self.find_astParent_until_top(downstream_cpg_node) # 获取AST最顶层节点

            condition_cpg_node: dict = self.find_control_condition(ast_top_cpg_node) # 获取控制语句的条件语句
            if not isinstance(condition_cpg_node, dict):
                continue

            cfg_out_call_nodes = self.find_cfgOut_until_call(condition_cpg_node, True) # 获取控制结构各个分支的首条语句
            for cfg_out_call_node in cfg_out_call_nodes:
                if not isinstance(cfg_out_call_node, dict):
                    continue

                # 检查下游是否有节点位于控制结构语句的分支中
                if self.check_dominate_node(cfg_out_call_node, downstream_ast_top_cpg_node):
                    upstram_id_dep_map[up_down_key] = True # 记录映射关系
                    upstram_id_dep_map[top_down_key] = True # 记录映射关系
                    # self.log_manager.log_info(f"Detect Control Dependency Between Nodes", False, self.indent_level + 2)
                    return True
                else:
                    upstram_id_dep_map[up_down_key] = False # 记录映射关系
                    upstram_id_dep_map[top_down_key] = False # 记录映射关系
        return False
    
    def find_reachable_call_nodes(self, cpg_node: dict):
        '''
        重复查找可达的CALL节点
        '''
        if isinstance(cpg_node, dict):
            node_id = cpg_node.get(NodeField.ID, None)
            if node_id is not None:
                query_stmts = []
                query_stmts.append(f"""val visited = new java.util.HashSet[Long]()""")
                query_stmts.append(f'cpg.{NodeType.ALL}.{NodeMethod.FILTER}(_.{NodeField.ID} == {node_id}' + str(node_id) + ').repeat(_.flatMap { node => if (!visited.' + NodeMethod.CONTAINS + '(node.' + NodeField.ID + ')) { visited.add(node.' + NodeField.ID + '); node.' + NodeField.REACHING_DEF_OUT + ' } else Iterator.empty }' + f')(_.until(_.hasLabel("{NodeLabel.CALL}")))')
                nodes = self.query(query_stmts)
                return nodes
        return []

    def is_controlled(self, source_node: dict, sink_node: dict):
        '''
        判断两个节点是否存在控制流依赖关系 (此函数要求两个CPG Nodes参数都是CALL类型)
        '''
        def extract_node_ids(nodes: list):
            node_ids = set()
            for node in nodes:
                if isinstance(node, dict):
                    node_id = node.get(NodeField.ID, None)
                    if node_id is not None:
                        node_ids.add(node_id)
            return node_ids

        if isinstance(source_node, dict) and isinstance(sink_node, dict):
            reachable_call_nodes = self.find_reachable_call_nodes(source_node)
            reachable_call_node_ids = extract_node_ids(reachable_call_nodes)

            source_id = source_node.get(NodeField.ID, None)
            if source_id is not None:
                reachable_call_node_ids.add(source_id)

            controlledBy_nodes = self.find_controlledBy_nodes(sink_node)
            controlledBy_node_ids = extract_node_ids(controlledBy_nodes)

            sink_id = sink_node.get(NodeField.ID, None)
            if sink_id is not None:
                controlledBy_node_ids.add(sink_id)

            if reachable_call_node_ids.intersection(controlledBy_node_ids):
                return True
        return False