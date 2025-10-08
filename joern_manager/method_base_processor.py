import copy
from typing import List

from joern_manager.method_parameter_processor import MethodParameterProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class MethodBaseProcessor(MethodParameterProcessor):
    '''
    此类中封装了方法的基础查询方法
    '''
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    # ======================================== Method Core Function Start ========================================

    def find_method_node_by_names_args(self, short_name: str, class_name: str, arg_types: list):
        '''
        [核心功能]: 根据方法名称、类名称、参数类型查找方法定义点的CPG Node
        '''

        def query_and_filter(cpg_type, conditions, restricts):
            '''
            查询并过滤查询结果
            '''
            restricts.append(f"{NodeMethod.FILTER}(node => ! node.{NodeConstraint.IS_EXTERNAL})") # 获取有方法体的方法
            nodes = self.find_nodes(cpg_type, conditions, restricts)
            result_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
            return result_nodes
        
        def sort_list_by_same_and_diff_type_num(data_list):
            '''
            (1) 按照字典中的 "same_type_num" 降序排列;
            (2) 当相同的时候按照 "diff_type_num" 升序排列
            '''
            return sorted(data_list, key = lambda x: (-x["same_type_num"], x["diff_type_num"]))
        
        def sort_candidate_method_nodes(method_cpg_nodes: List[dict], arg_types: List[str]):
            '''
            对候选的目标方法节点进行排序
            '''
            if not isinstance(method_cpg_nodes, list):
                return []

            for node in method_cpg_nodes:
                parameter_tyeps = self.get_parameter_types(node)
                same_types = self.get_same_types_between_method_and_argument(node, arg_types)
                node["same_type_num"] = len(same_types) # 相同类型参数数量
                node["diff_type_num"] = abs(len(parameter_tyeps) - len(arg_types)) # 参数数量差额
            # [方法体推断启发式规则]: 按照相似类型数量+参数数量差额推断正确的方法体 TODO: 此处只是一个排序算法,具体表现待观察
            method_cpg_nodes = sort_list_by_same_and_diff_type_num(method_cpg_nodes)
            return method_cpg_nodes

        def add_argument_conditions(origin_conditions: list, arg_types: list):
            '''
            添加形参类型约束条件
            '''
            conditions = copy.deepcopy(origin_conditions)
            if arg_types:
                param_condition = "("
                for i in range(len(arg_types)):
                    param_condition += f'node.{NodeField.FULL_NAME}.{NodeMethod.CONTAINS}("{arg_types[i]}")'
                    if i != len(arg_types) - 1:
                        param_condition += " && "
                    else:
                        param_condition += ")"
                conditions.append(param_condition)
            return conditions
        
        def is_parent_class(parent_class_names: list, class_name: str):
            '''
            判断某个类是否是当前分析类的父类
            '''
            if parent_class_names and class_name:
                if class_name in parent_class_names:
                    return True

                for parent_class_name in parent_class_names:
                    if parent_class_name.find(class_name) != -1 or class_name.find(parent_class_name) != -1:
                        return True
            
            return False

        # 构造必要条件
        if not short_name:
            return None

        necessary_conditions1 = [f'node.{NodeField.NAME}=="{short_name}"']
        necessary_conditions2 = copy.deepcopy(necessary_conditions1)
        parent_class_names = []
        if class_name:
            # 获取父类名称列表
            parent_class_names = self.get_all_parent_class_name(class_name)
            necessary_conditions1.append(f'node.{NodeField.FULL_NAME}.contains("{class_name}")')

        # [方法体推断#1]: 根据方法名称,所属类名称,形参类型推断方法体 (arg_types实际上是实参的类型)
        conditions1 = add_argument_conditions(necessary_conditions1, arg_types)
        method_cpg_nodes = query_and_filter("method", conditions1, [])
        method_cpg_nodes = sort_candidate_method_nodes(method_cpg_nodes, arg_types)
        if isinstance(method_cpg_nodes, list) and method_cpg_nodes:
            return method_cpg_nodes[0]
            
        # [方法体推断#2]: 根据方法名称,所属类的继承关系,形参类型推断方法体
        if class_name:
            conditions2 = add_argument_conditions(necessary_conditions2, arg_types)
            method_cpg_nodes = query_and_filter("method", conditions2, [])
            method_cpg_nodes = sort_candidate_method_nodes(method_cpg_nodes, arg_types)

            if isinstance(method_cpg_nodes, list) and method_cpg_nodes:
                for method_cpg_node in method_cpg_nodes:
                    class_cpg_node = self.find_belong_class(method_cpg_node)
                    if isinstance(class_cpg_node, dict):
                        method_belong_class_name = class_cpg_node.get(NodeField.FULL_NAME, None)
                        if is_parent_class(parent_class_names, method_belong_class_name):
                            return method_cpg_node

        # [方法体推断#3]: 根据方法名称,所属类名称,形参数量推断方法体 (有时候形参和实参的类型不一致)
        conditions3 = copy.deepcopy(necessary_conditions1)
        method_cpg_nodes = query_and_filter("method", conditions3, [])
        method_cpg_nodes = sort_candidate_method_nodes(method_cpg_nodes, arg_types)
        if isinstance(method_cpg_nodes, list) and method_cpg_nodes:
            return method_cpg_nodes[0]

        # [方法体推断#4]: 根据方法名称,所属类的继承关系,形参数量推断方法体
        if class_name:
            conditions4 = copy.deepcopy(necessary_conditions2)
            method_cpg_nodes = query_and_filter("method", conditions4, [])
            method_cpg_nodes = sort_candidate_method_nodes(method_cpg_nodes, arg_types)
            
            if isinstance(method_cpg_nodes, list) and method_cpg_nodes:
                for method_cpg_node in method_cpg_nodes:
                    class_cpg_node = self.find_belong_class(method_cpg_node)
                    if isinstance(class_cpg_node, dict):
                        method_belong_class_name = class_cpg_node.get(NodeField.FULL_NAME, None)
                        if is_parent_class(parent_class_names, method_belong_class_name):
                            return method_cpg_node

        return None

    def find_belong_method(self, cpg_node: dict):
        '''
        [核心方法]: 找到语句所属的函数定义点
        '''
        def find_reachingDefIn_nodes(cpg_node: dict):
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

        if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys():
            method_nodes = list()
            if NodeField.LABEL in cpg_node.keys():
                if cpg_node[NodeField.LABEL] == NodeLabel.METHOD_PARAMETER_IN:
                    # 对于入参节点,只需找到其上层可达点,即是METHOD节点
                    method_nodes = find_reachingDefIn_nodes(cpg_node)
                elif cpg_node[NodeField.LABEL] == NodeLabel.METHOD_RETURN:
                    # 对于函数返回节点,其AST上层节点即是METHOD节点
                    method_nodes = self.find_nodes(
                        cpg_type = NodeType.ALL,
                        conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
                        restricts = [NodeField.AST_IN]
                    )
                else:
                    # 其它类型节点则需根据dominatedBy关系来查找METHOD节点
                    node_id = cpg_node.get(NodeField.ID, None)
                    if cpg_node[NodeField.LABEL] != NodeLabel.CALL:
                        call_cpg_node = self.find_astParent_until_call_or_control(cpg_node)
                        if isinstance(call_cpg_node, dict) and NodeField.ID in call_cpg_node.keys():
                            node_id = call_cpg_node.get(NodeField.ID, None)
                    method_nodes = self.find_nodes(
                        cpg_type = NodeType.ALL,
                        conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
                        restricts = [NodeField.DOMINATED_BY, NodeConstraint.IS_METHOD, f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})"]
                    )
            if method_nodes:
                for node in method_nodes:
                    if isinstance(node, dict):
                        if NodeField.LABEL in node.keys():
                            if node[NodeField.LABEL] == NodeLabel.METHOD:
                                if NodeField.AST_PARENT_TYPE in node.keys():
                                    if node[NodeField.AST_PARENT_TYPE] in [NodeLabel.METHOD, "<empty>"]:
                                        return node
                                    elif node[NodeField.AST_PARENT_TYPE] == NodeLabel.TYPE_DECL: # TODO: 仍然需要观察TYPE_DECL是否合适
                                        if NodeField.AST_PARENT_FULL_NAME in node.keys():
                                            if not node[NodeField.AST_PARENT_FULL_NAME].endswith(".php:<global>"):
                                                return node
        return None

    # ======================================== Method Core Function End ========================================

    # ======================================== Method Base Information Process Start ========================================

    def get_method_short_name(self, cpg_node: dict):
        '''
        获取方法短名称,例如 `getName`
        '''
        if isinstance(cpg_node, dict):
            if cpg_node.get(NodeField.NAME, None):
                return cpg_node[NodeField.NAME]
            else:
                method_full_name = "None"
                if NodeField.METHOD_FULL_NAME in cpg_node.keys():
                    method_full_name = cpg_node[NodeField.METHOD_FULL_NAME]
                elif NodeField.FULL_NAME in cpg_node.keys():
                    method_full_name = cpg_node[NodeField.FULL_NAME]
                method_full_name = method_full_name.replace(".<returnValue>", "")

                method_short_name = None
                if method_full_name.find(":") != -1:
                    method_full_name = method_full_name[:method_full_name.find(":")]
                if method_full_name.find("->") != -1:
                    method_short_name = method_full_name.split("->")[-1]
                else:
                    method_short_name = method_full_name.split(".")[-1]
                return method_short_name
        
        return None

    def get_method_full_name(self, cpg_node: dict):
        '''
        去除full name中的.<returnValue>
        '''
        method_full_name: str = None
        if isinstance(cpg_node, dict):
            if NodeField.METHOD_FULL_NAME in cpg_node.keys():
                method_full_name = cpg_node[NodeField.METHOD_FULL_NAME]
            elif NodeField.FULL_NAME in cpg_node.keys():
                method_full_name = cpg_node[NodeField.FULL_NAME]

        if method_full_name:
            method_full_name = method_full_name.replace(".<returnValue>", "").replace("<unresolvedNamespace>", "").strip("\\")
        return method_full_name

    def find_method_call_receivers(self, cpg_node: dict):
        '''
        找到函数调用的接收者
        '''
        if not isinstance(cpg_node, dict):
            return []

        node_id = cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f"node.{NodeField.ID}=={str(node_id)}"],
            restricts = [NodeField.RECEIVER]
        )

        receiver_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        receiver_nodes = self.remove_duplicate_nodes(receiver_nodes)
        return receiver_nodes

    def get_method_real_full_name(self, cpg_node: dict):
        '''
        派生函数以获取真实的full name
        '''
        if not isinstance(cpg_node, dict):
            return None

        method_full_name: str = cpg_node.get(NodeField.METHOD_FULL_NAME, "None")
        method_full_name = method_full_name.replace(".<returnValue>", "")
        if not self.check_full_name(method_full_name):
            receiver_nodes = self.find_method_call_receivers(cpg_node)
            for receiver_node in receiver_nodes:
                if NodeField.TYPE_FULL_NAME in receiver_node.keys():
                    receiver_name = receiver_node[NodeField.TYPE_FULL_NAME]

                    all_parent_names = self.get_all_parent_class_name(receiver_name)
                    for parent_name in all_parent_names:
                        new_method_full_name = method_full_name.replace(receiver_name, parent_name)
                        if self.check_full_name(new_method_full_name):
                            return new_method_full_name # 当新构造的函数名称能访问时,说明找到了合适的函数名称

        self.log_manager.log_info(f"Get Real Full Name: {method_full_name}", False, self.indent_level)
        return method_full_name

    def get_cpg_info(self, cpg_node: dict):
        '''
        获取CPG Node简短信息
        '''
        cpg_info = ""
        if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys():
            cpg_info += str(cpg_node.get(NodeField.ID, None))
            if NodeField.LABEL in cpg_node.keys():
                cpg_info = cpg_info + " " + cpg_node[NodeField.LABEL]
            if NodeField.CODE in cpg_node.keys():
                cpg_info = cpg_info + " " + cpg_node[NodeField.CODE]
            elif NodeField.NAME in cpg_node.keys():
                cpg_info = cpg_info + " " + cpg_node[NodeField.NAME]
        return cpg_info.strip()

    def check_full_name(self, method_full_name):
        '''
        检查函数全名是否存在
        '''
        method_full_name = method_full_name.replace(".<returnValue>", "")
        method_nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
            restricts = []
        )
        if method_nodes != []:
            return True
        return False

    def find_method(self, class_name: str, method_name: str):
        '''
        根据方法所属类名和方法名称查找方法CPG Node
        '''
        nodes = self.find_nodes(
            cpg_type=NodeType.METHOD,
            conditions=[
                f"node.{NodeField.FULL_NAME}.contains(\"{class_name}\") && node.{NodeField.NAME}==\"{method_name}\""],
            restricts=[]
        )
        
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    return node
        return None

    def find_method_node_by_names(self, short_name: str, class_name: str):
        '''
        根据方法名称和类名称查找方法定义点的CPG Node
        '''
        conditions = []
        if short_name:
            conditions.append(f'node.{NodeField.NAME}=="{short_name}"')
        if class_name:
            conditions.append(f'node.{NodeField.FULL_NAME}.contains("{class_name}")')
        if conditions:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = conditions,
                restricts = ["take(2)"]
            )
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        return node
        return None

    def find_method_by_fullname(self, method_full_name: str):
        '''
        根据方法签名查找方法对应的 CPG 节点 (传入方法签名)
        '''
        if method_full_name is None:
            return None
        method_full_name = method_full_name.replace(".<returnValue>", "").replace(":<unresolvedSignature>(1)", "")
        method_nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
            restricts = []
        )
        if isinstance(method_nodes, list):
            for method_node in method_nodes:
                if isinstance(method_node, dict):
                    return method_node
        return None

    def find_method_by_node_fullname(self, cpg_node: dict):
        '''
        根据方法签名查找方法对应的 CPG 节点 (传入CPG Node)
        '''
        method_full_name = self.get_method_full_name(cpg_node)
        method_nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
            restricts = []
        )
        if isinstance(method_nodes, list):
            for method_node in method_nodes:
                if isinstance(method_node, dict):
                    return method_node
        else:
            return None
    
    def find_method_parent(self, cpg_node: dict, gap_num: int):
        '''
        向上查找函数的父节点,gap_num代表层级数量
        '''
        gaps = list()
        for i in range(0, gap_num):
            gaps.append(NodeField.AST_PARENT)
        method_full_name = self.get_method_full_name(cpg_node)
        method_parent_nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [f'node.{NodeField.FULL_NAME} == "{method_full_name}"'],
            restricts = gaps
        )
        if method_parent_nodes:
            return method_parent_nodes[0]
        return None

    def query_for_methods_with_class(self, class_name: str, package: str):
        '''
        查询指定 Package 和 Class 中的所有 Method 信息
        '''
        method_cpg_nodes = []
        method_query = [f"""cpg.{NodeType.TYPE_DECL}.{NodeField.FULL_NAME}("{package}.{class_name.replace('$','.')}").method.l"""]
        nodes = self.query(method_query)
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    # 此处处理一下两个行号
                    start_line = self.content_to_num(node.get(NodeField.LINE_NUMBER, None))
                    end_line = self.content_to_num(node.get(NodeField.LINE_NUMBER_END, None))

                    node[NodeField.LINE_NUMBER] = start_line
                    node[NodeField.LINE_NUMBER_END] = end_line
                    method_cpg_nodes.append(node)
        return method_cpg_nodes

    # 直接用method full name查询
    def query_method_node(self, method_full_name):
        conditions = list()
        if method_full_name is not None:
            conditions.append(f'node.{NodeField.FULL_NAME}=="{method_full_name}"')
        nodes = self.find_nodes(
            cpg_type=NodeType.METHOD,
            conditions=conditions,
            restricts=[]
        )
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    return node
        return {}

    def is_obj_call(self, cpg_node: dict):
        '''
        判断函数调用是否是类的函数(检查上三辈)
        '''
        for gap_num in range(1, 4):
            method_parent_node = self.find_method_parent(cpg_node, gap_num)
            if method_parent_node:
                if isinstance(method_parent_node, dict):
                    if method_parent_node[NodeField.LABEL].strip() == NodeLabel.TYPE_DECL:
                        return True
            else:
                break
        return False

    def is_common_call(self, cpg_node: dict):
        '''
        判断函数调用是否是普通函数
        '''
        # 根据cpg_node[NodeField.LABEL]是否为"METHOD", "NAMESPACE_BLOCK"不足以判断函数类型
        for gap_num in range(1, 4):
            method_parent_node = self.find_method_parent(cpg_node, gap_num)
            if method_parent_node and isinstance(method_parent_node, dict):
                if method_parent_node[NodeField.LABEL].strip() == NodeLabel.TYPE_DECL:
                    return False
            else:
                break
        return True
    
    def is_method_call(self, cpg_node: dict):
        '''
        快速判断是否是函数调用节点,适用于数据流分析
        '''
        if isinstance(cpg_node, dict):
            cpg_label = cpg_node.get(NodeField.LABEL, None)
            cpg_methodFullName = cpg_node.get(NodeField.METHOD_FULL_NAME, None)
            if cpg_label == NodeLabel.CALL:
                if cpg_methodFullName:
                    if cpg_methodFullName.find("<operator>") == -1:
                        return True
        return False

    def is_external(self, cpg_node: dict):
        '''
        判断函数是否是外部函数( e.g. addslashes()就是一个外部函数 )
        '''
        external_flag = False
        real_full_name = None
        if cpg_node is not None:
            real_full_name = self.get_method_real_full_name(cpg_node)
            method_node = self.find_method_by_fullname(real_full_name)
            # method_node = self.find_method_by_node_fullname(cpg_node)
            if method_node:
                if NodeField.IS_EXTERNAL in method_node.keys():
                    external_flag = (str(method_node[NodeField.IS_EXTERNAL]).lower().strip() == "true")
            # 处理Joern未能解决的global函数
            if external_flag:
                global_short_name = self.get_method_short_name(cpg_node)
                if global_short_name != real_full_name:
                    global_method_node = self.find_method_by_fullname(global_short_name)
                    if global_method_node is not None and isinstance(global_method_node, dict):
                        if NodeField.AST_PARENT_FULL_NAME in global_method_node.keys():
                            if global_method_node[NodeField.AST_PARENT_FULL_NAME].find("php:<global>") != -1:
                                if NodeField.IS_EXTERNAL in global_method_node.keys():
                                    real_full_name = global_short_name
                                    external_flag = (str(global_method_node[NodeField.IS_EXTERNAL]).lower().strip() == "true")
        return external_flag, real_full_name

    def is_abstract_method(self, method_node: dict):
        '''
        判断一个方法是否是抽象方法
        '''
        if isinstance(method_node, dict):
            method_id = method_node.get(NodeField.ID, None)
            method_code: str = method_node.get(NodeField.CODE, None)
            method_label = method_node.get(NodeField.LABEL, None)
            if method_id is not None and method_label == NodeLabel.METHOD and method_code:
                # (1) 首先检查方法定义代码中是否有abstract关键字
                if method_code.find("abstract ") != -1:
                    return True
                
                # (2) 检查所属类的定义中是否有interface关键字
                class_node = self.find_belong_class(method_node)
                if isinstance(class_node, dict) and class_node.get(NodeField.CODE, "None").find("interface ") != -1:
                    return True
                
                # (3) 检查方法体是否有内容
                exists_method_content = False
                query_statement = f"cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node=>node.{NodeField.ID}=={method_id}).{NodeField.AST}.{NodeConstraint.IS_CALL}.take(2).toJson"
                nodes = self.find_nodes(None, None, None, query_statement)
                if isinstance(nodes, list):
                    for node in nodes:
                        if isinstance(node, dict):
                            exists_method_content = True
                            break
                if not exists_method_content:
                    # 方法体内不存在内容时认为是抽象方法
                    return True
        return False

    def is_related_to_method_field(self, method_cpg_node: dict, cpg_node: dict) -> bool:
        '''
        检查CPG Node是否与函数内部某个Field节点有关
        '''
        if not isinstance(method_cpg_node, dict) or not isinstance(cpg_node, dict):
            return None, False

        # (0) 获取基本信息
        method_id = method_cpg_node.get(NodeField.ID, None)
        line_num = cpg_node.get(NodeField.LINE_NUMBER, None)
        variable_name = cpg_node.get(NodeField.CODE, None)

        if method_id is None or variable_name is None:
            return None, False

        # (1) 构建查询的约束条件
        restricts1 = []
        restricts1.append(f'{NodeMethod.FILTER}(node => node.{NodeField.ID}=={method_id})')
        restricts1.append(f'{NodeField.AST}')
        restricts1.append(f'{NodeConstraint.IS_CALL}')
        restricts1.append(f'{NodeMethod.FILTER}(node => node.{NodeField.METHOD_FULL_NAME} == "{NodeOperator.ASSIGNMENT}" && node.{NodeField.CODE}.contains("this.") && node.{NodeField.CODE}.contains("{variable_name}"))')
        
        restricts2 = copy.deepcopy(restricts1)
        if line_num is not None:
            restricts1.append(f'{NodeMethod.FILTER}(node => node.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) > {line_num})') # TODO: 此处的约束条件在使用node.{NodeField.LOCATION}.lineNumber属性时查询出错

        # (2) 查询Field节点
        nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [],
            restricts = restricts1
        )

        if nodes == [] and line_num is not None:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [],
                restricts = restricts2
            )

        # (3) 筛选查询结果
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    target_nodes: List[dict] = self.find_assign_targets(node)
                    if isinstance(target_nodes, list):
                        for target_node in target_nodes:
                            if isinstance(target_node, dict):
                                target_node_code = target_node.get(NodeField.CODE, None)
                                # 根据左值节点的代码进行筛选
                                if target_node_code is not None and target_node_code != variable_name and target_node_code.find("this.") != -1:
                                    return target_node, True

        return None, False

    # ======================================== Method Base Information Process End ========================================

    # ======================================== Variable Handling Logic Related to Methods Start ========================================

    def get_index_access_nodes(self, method_cpg_node: dict) -> List[dict]:
        '''
        获取方法体内部的访问索引的语句
        '''
        index_access_nodes = []

        if not isinstance(method_cpg_node, dict):
            return []
        
        method_id = method_cpg_node.get(NodeField.ID, None)
        nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [f'node.{NodeField.ID} == {method_id}'],
            restricts = [NodeField.AST, NodeConstraint.IS_CALL, f'{NodeMethod.FILTER}(node => node.{NodeField.METHOD_FULL_NAME} == "{NodeOperator.FieldAccess}")', 'dedup']
        )
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    index_access_nodes.append(node)
        return index_access_nodes
    
    def find_var_nodes_in_method(self, method_cpg_node: dict, variable_name: str, need_all: bool = False) -> list:
        '''
        根据变量名称,在函数内部找到其相应的数据节点
        '''
        variable_cpg_nodes = list()
        fullname = None
        if isinstance(method_cpg_node, dict):
            fullname = self.get_method_full_name(method_cpg_node)
        if fullname:
            num_limit = f"{NodeMethod.SORT_BY}(node=>node.{NodeField.LINE_NUMBER})"
            if not need_all:
                num_limit = f"{NodeMethod.SORT_BY}(node=>node.{NodeField.LINE_NUMBER}).take(2)"
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [],
                restricts = [
                    f'{NodeMethod.FILTER}(node=>node.{NodeField.FULL_NAME}=="{fullname}")',
                    NodeType.CALL,
                    f'{NodeMethod.FILTER}(node=>node.{NodeField.CODE}.contains("{variable_name}"))',
                    f"{num_limit}"
                ]
            )
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        if NodeField.ID in node.keys():
                            variable_cpg_nodes.append(node)
                            if not need_all:
                                break
        return variable_cpg_nodes

    def find_var_node_in_method(self, method_cpg_node: dict, variable_name: str, is_patched: bool, line_start: int, line_end: int):
        '''
        查找在方法内指定区间内的变量的CPG节点
        '''
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
        restricts.append("ast")
        
        # 获取变量类型
        if not variable_name or variable_name == "this":
            return None
        node_type = NodeConstraint.IS_IDENTIFIER if variable_name.find(".") == -1 else NodeConstraint.IS_CALL
        restricts.append(node_type)

        # 构造变量名称约束条件
        var_name_constraint = f'{NodeMethod.FILTER}(node=>node.{NodeField.CODE}=="{variable_name}")'
        restricts.append(var_name_constraint)

        # 构造行号区间的约束条件
        line_num_constraint = ""
        if not is_patched and isinstance(line_start, int) and isinstance(line_end, int):
            if line_start == line_end:
                line_num_constraint = f'{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0)=={line_start})'
            elif line_start < line_end:
                line_num_constraint = f'{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) >= {line_start}).{NodeMethod.FILTER}(x=>x.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}.{NodeMethod.MAP}(_.intValue()).getOrElse(0) <= {line_end})'
        if line_num_constraint:
            restricts.append(line_num_constraint)
        
        # 添加数量约束
        restricts.append(f"{NodeMethod.SORT_BY}(node=>node.{NodeField.LINE_NUMBER}).take(2)")

        nodes = self.find_nodes(
            cpg_type = NodeType.METHOD,
            conditions = [],
            restricts = restricts
        )
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict) and NodeField.ID in node.keys():
                    return node
        return None
    
    def find_candidate_data_node(self, method_name: str, variabele_name: str):
        '''
        获取候选的数据节点
        '''
        # (1) 构建方法名称约束条件
        method_condition = ""
        if method_name:
            method_condition = f'{NodeMethod.FILTER}(node=>node.{NodeField.NAME}=="{method_name}")'

        nodes = []
        if method_condition:
            # (2) 查找普通标识符节点
            identifier_restrict = f'{NodeMethod.FILTER}(node=>node.{NodeField.CODE}=="{variabele_name}")'
            nodes1 = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [],
                restricts = [f'{method_condition}', NodeField.AST, NodeConstraint.IS_IDENTIFIER, identifier_restrict, f"{NodeMethod.SORT_BY}(node=>node.{NodeField.LINE_NUMBER})", "take(10)"]
            )
            if isinstance(nodes1, list):
                nodes.extend(nodes1)

            # (3) 查找fieldAccessd节点
            if variabele_name.find(".") == -1:
                variabele_name = f"this.{variabele_name}"
            field_restrict = f'{NodeMethod.FILTER}(node=>node.{NodeField.CODE}=="{variabele_name}")'
            nodes2 = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [],
                restricts = [f'{method_condition}', NodeField.AST, NodeConstraint.IS_CALL, field_restrict, f"{NodeMethod.SORT_BY}(node=>node.{NodeField.LINE_NUMBER})", "take(10)"]
            )
            if isinstance(nodes2, list):
                nodes.extend(nodes2)

        # (4) 获得结果,只取第一条 TODO:待优化
        for node in nodes:
            if isinstance(node, dict):
                return node
        return None

    def query_local_variables_inMethod(self, method_full_name):
        query_stmt = []
        query = """cpg.method.fullNameExact("""+ '"' + method_full_name + '"' +""")
                    .flatMap { m =>
                    val params = m.parameter.toSeq
                    val locals = m.ast.isLocal.toSeq
                    params ++ locals 
                    }.dedup
                   .l"""
        query_stmt.append(query)

        try:
            return self.query(query_stmt)
        except Exception as e:
            self.log_manager.log_info(f"CPG Query Fail: {query_stmt}", False, self.indent_level)
            raise (e)

    def query_all_variables_in_method(self, method_full_name:str):
        result_nodes = list()
        query_stmt = []
        ### 临时变量
        query_stmt.append(f"""var m = cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node => node.{NodeField.FULL_NAME} == "{method_full_name}")""")
        query_stmt.append(f"""m.local.l""")
        result_nodes.extend(self.query(query_stmt))
        ## 提取所有用到的变量引用（标识符）
        query_stmt = []
        query_stmt.append(f"""var m = cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node => node.{NodeField.FULL_NAME} == "{method_full_name}")""")
        query_stmt.append(f"""m.ast.{NodeConstraint.IS_IDENTIFIER}.l""")
        result_nodes.extend(self.query(query_stmt))
        ### 提取所有方法参数
        query_stmt = []
        query_stmt.append(f"""var m = cpg.{NodeType.METHOD}.{NodeMethod.FILTER}(node => node.{NodeField.FULL_NAME} == "{method_full_name}")""")
        query_stmt.append(f"""m.ast.isParameter.l""")
        result_nodes.extend(self.query(query_stmt))

        return result_nodes
    # ======================================== Variable Handling Logic Related to Methods End ========================================