import copy
from typing import List

from joern_manager.method_argument_processor import MethodArgumentProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class MethodProcessor(MethodArgumentProcessor):
    '''
    此类中主要处理方法之间的调用关系
    '''
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)
    
    def find_call_edge_successors(self, cpg_node: dict, real_full_name: str):
        # 找到函数调用的CFG子节点
        nodes = list()
        method_cpg_id = None
        method_node = self.find_method_by_fullname(real_full_name)
        if isinstance(method_node, dict):
            if NodeField.ID in method_node.keys():
                method_cpg_id = method_node.get(NodeField.ID, None)
                cfg_out_call_nodes = self.find_cfgOut_until_call(method_node, False)
                for node in cfg_out_call_nodes:
                    nodes.append(self.find_astParent_until_top(node))
        successors = self.remove_duplicate_nodes(nodes)
        return method_cpg_id, successors

    def find_call_sites(self, cpg_node: dict):
        # 获取函数调用点
        # TODO: 2024-05-26 发现Joern解析PHP global函数时可能存在问题,这导致使用callIn函数失效,因此暂时不能使用callIn
        call_sites = []
        cpg_param_types = self.get_param_types(cpg_node)
        method_short_name = self.get_method_short_name(cpg_node)
        
        nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f'node.{NodeField.NAME} == "{method_short_name}"'],
            restricts = [] # f"{NodeMethod.MAP}(x=> (x.node.{NodeField.ID}, x.node.code, x.node.location.filename, x.node.location.{NodeField.LINE_NUMBER}, x.node.{NodeField.METHOD_FULL_NAME}))"
        )
    
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    node_param_types = self.get_param_types(node)
                    if len(cpg_param_types) == len(node_param_types):
                        # 仅仅根据函数名称来获取目标函数的调用点是存在很多误差的,这里加上参数数量检查机制,以略微提升准确度
                        call_sites.append(node)
        return call_sites
    
    def find_top_call_site(self, file_relative_path: str, cpg_node: dict):
        '''
        递归找到一条语句最终的调用点
        '''
        call_site = None
        method_node = self.find_belong_method(cpg_node)
        while method_node is not None:
            call_sites = list()
            temp_call_sites1 = self.find_call_sites(method_node)
            # 对temp_call_sites1按照filename的目录结构排序
            nums = list()
            temp_call_sites2 = list()
            for node in temp_call_sites1:
                nums.append(len(node[NodeField.FILE_NAME].split("/")))
            nums = sorted(list(set(nums)))
            for num in nums:
                for node in temp_call_sites1:
                    if len(node[NodeField.FILE_NAME].split("/")) == num:
                        temp_call_sites2.append(node)
            # 对temp_call_sites2按照file_relative_path进行筛选
            for node in temp_call_sites2:
                if node[NodeField.FILE_NAME] == file_relative_path:
                    call_sites.append(node)
            if call_sites == []:
                call_sites = copy.deepcopy(temp_call_sites2)
            # 从call_sites中挑第一个作为待分析的起始点(TODO:这里实际可以获取多个可能的起始点,但暂时只用了第一个)
            is_new_call_site = False
            if call_sites:
                for node in call_sites:
                    if isinstance(node, dict):
                        call_site = node
                        is_new_call_site = True
                        break
            if is_new_call_site:
                method_node = self.find_belong_method(call_site)
            else:
                method_node = None
        return call_site

    def find_callins(self, cpg_info: any):
        '''
        根据函数签名(fullName)获取函数的所有被调用点

        parameter
        --------
        cpg_info: 可能是一个CPG Node,也可能是字符串格式的函数签名
        '''
        callin_nodes = list()
        fullname = None
        if isinstance(cpg_info, dict):
            fullname = self.get_method_full_name(cpg_info)
        elif isinstance(cpg_info, str):
            fullname = cpg_info
        if fullname:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [f'node.{NodeField.FULL_NAME}=="{fullname}"'],
                restricts = [NodeField.CALL_IN, f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})"]
            )
            callin_nodes = [node for node in nodes if isinstance(node, dict) and NodeField.ID in node.keys()] if isinstance(nodes, list) else []
        return callin_nodes

    def find_callees(self, cpg_info: any):
        '''
        获取函数内部调用其它函数的节点

        parameter
        --------
        cpg_info: 可能是一个CPG Node,也可能是字符串格式的函数签名
        '''
        callee_nodes = list()
        fullname = None
        if isinstance(cpg_info, dict):
            fullname = self.get_method_full_name(cpg_info)
        elif isinstance(cpg_info, str):
            fullname = cpg_info
        if fullname:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [],
                restricts = [
                    f'{NodeMethod.FILTER}(node=>node.{NodeField.FULL_NAME}=="{fullname}")',
                    NodeType.CALL,
                    f'{NodeMethod.FILTER}(node=>(node.{NodeField.CODE}.{NodeMethod.CONTAINS}("(") && node.{NodeField.CODE}.{NodeMethod.CONTAINS}(")") && (! List("{NodeOperator.ASSIGNMENT}", {NodeOperator.ALLOC}).{NodeMethod.CONTAINS}(node.{NodeField.METHOD_FULL_NAME})) && (! node.{NodeField.METHOD_FULL_NAME}.{NodeMethod.STARTS_WITH}("java.")) && (! node.{NodeField.METHOD_FULL_NAME}.contains("<init>"))))'
                ]
            )
            callee_nodes = [node for node in nodes if isinstance(node, dict) and NodeField.ID in node.keys()] if isinstance(nodes, list) else []
        return callee_nodes
    
    def find_callers(self, cpg_info: any):
        '''
        查找函数在哪些函数中被调用过

        cpg_info: 既可以是函数签名,也可以是一个METHOD/CALL等多种类型的CPG Node(MEMBER类型不行)
        '''
        def get_fullname(cpg_info: any):
            if isinstance(cpg_info, str):
                return cpg_info
            elif isinstance(cpg_info, dict):
                if NodeField.LABEL in cpg_info.keys():
                    if cpg_info[NodeField.LABEL] == NodeLabel.METHOD:
                        return self.get_method_full_name(cpg_info)
                    elif cpg_info[NodeField.LABEL] in [NodeLabel.CALL, NodeLabel.IDENTIFIER]:
                        # 此时cpg_info位于方法内部
                        method_node = self.find_belong_method(cpg_info)
                        return self.get_method_full_name(method_node)
            return None

        caller_nodes: List[dict] = list()
        fullname = get_fullname(cpg_info)
        if fullname:
            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD,
                conditions = [f'node.{NodeField.FULL_NAME}=="{fullname}"'],
                restricts = [NodeField.CALLER]
            )
            for node in nodes:
                if isinstance(node, dict) and NodeField.FULL_NAME in node.keys():
                    caller_nodes.append(node)
        return caller_nodes
    
    def find_top_callers(self, cpg_info: any):
        '''
        迭代找到最上层的调用函数 func1 => func2 => fun3 ...
        '''
        caller_nodes: List[dict] = list()
        processed_ids = list()
        stack = self.find_callers(cpg_info)
        while stack:
            cpg_node = stack.pop()
            if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys():
                if cpg_node.get(NodeField.ID, None) not in processed_ids:
                    processed_ids.append(cpg_node.get(NodeField.ID, None))
                    temp_callers = self.find_callers(cpg_node)
                    if temp_callers:
                        # 如果当前分析节点有调用点,就继续分析其调用点
                        for node in temp_callers:
                            stack.append(node)
                    else:
                        # 否则认为已经找到最上层调用点
                        caller_nodes.append(cpg_node)
        caller_nodes = self.remove_duplicate_nodes(caller_nodes)
        return caller_nodes

    def find_top_wrapper_method_nodes(self, method_cpg_node: dict, special_method_names: list, analysis_depth: int, need_top: bool):
        '''
        查找一个方法最顶层的封装方法 (通过是否有返回值来检查)
        '''
        def need_analysis(method_node: dict, depth: int, analyzed_method_signatures: set):
            '''
            判断一个方法是否需要分析
            '''
            if not isinstance(method_node, dict):
                return False
            elif depth < 0:
                return False
            elif method_node.get(NodeField.FULL_NAME, None) is None:
                return False
            elif method_node.get(NodeField.FULL_NAME, None) in analyzed_method_signatures:
                return False
            else:
                analyzed_method_signatures.add(method_node.get(NodeField.FULL_NAME, None))
                return True
        
        def maybe_sink(method_node: dict):
            '''
            判断中间结果是否可能是Sink API
            '''
            if isinstance(special_method_names, list) and method_node.get(NodeField.NAME, None):
                # 情况一: 发现同名方法
                if method_node.get(NodeField.NAME, None) in special_method_names:
                    return True
                
                # 情况二: 发现相似命名的方法
                for special_method_name in special_method_names:
                    method_name = method_node.get(NodeField.NAME, "None").lower()
                    if method_name.find(special_method_name.lower()) != -1 or special_method_name.lower().find(method_name) != -1:
                        return True

                # [启发式规则#12] 情况三: 如果其返回值类型是布尔类型,其参数可能是Sink APIs运行后的结果,此时将其也加入待分析列表中
                if str(method_node.get(NodeField.FULL_NAME, None)).find(":boolean(") != -1:
                    return True
                
                return False

        top_wrapper_nodes = []
        analysis_method_stack = []
        analyzed_method_signatures = set()
        analysis_method_stack.append((method_cpg_node, analysis_depth))

        while analysis_method_stack != []:
            method_node, depth = analysis_method_stack.pop()

            if not need_analysis(method_node, depth, analyzed_method_signatures):
                if need_top:
                    top_wrapper_nodes.append(method_node)
                continue

            # (1) 检查其是否是所关注的特殊方法,如果是的话就将其加入到结果中
            if maybe_sink(method_node):
                top_wrapper_nodes.append(method_node)

            # (2) 首先用Joern自带的callIn接口去找其直接调用的节点
            callin_cpg_nodes = self.find_callins(method_node)

            # (3) 然后根据函数名称去找到其他可能的函数调用点
            if not callin_cpg_nodes:
                call_sites = self.find_call_sites(method_node)
                callin_cpg_nodes.extend(call_sites)
                callin_cpg_nodes = self.remove_duplicate_nodes(callin_cpg_nodes)

            if not callin_cpg_nodes:
                # (4) 如果没有找到任何调用点,那么就认为已经找到了顶层调用点
                top_wrapper_nodes.append(method_node)
            else:
                for callin_cpg_node in callin_cpg_nodes:

                    # (5) 对于每个函数调用点,检查其接收者是否和函数返回值相关
                    belong_method_node = self.find_belong_method(callin_cpg_node)

                    related_to_return = False
                    receiver_nodes = self.find_method_call_receivers(callin_cpg_node)
                    for receiver_node in receiver_nodes:
                        if self.is_related_to_method_return(receiver_node):
                            related_to_return = True
                            break

                    if related_to_return:
                        # (6) 如果相关的话,就还需继续向上找Wrapper函数
                        analysis_method_stack.append((belong_method_node, depth - 1)) # 注意:此处分析深度减一
                    else:
                        # (7) 如果无关,那么也就认为当前分析的method_node就是顶层wrapper函数
                        top_wrapper_nodes.append(method_node)

        # (8) 实在啥也找不到时,就返回原始输入节点
        if top_wrapper_nodes == []:
            top_wrapper_nodes.append(method_cpg_node)

        top_wrapper_nodes = self.remove_duplicate_nodes(top_wrapper_nodes)

        return top_wrapper_nodes

    def get_caller_infos(self, method_cpg_node: dict, call_max_depth: int = 3):
        '''
        根据 method_cpg_node 更新上层调用点信息

        keep_num => 每层保留的caller数目
        call_max_depth => 向上查找的层数(1表示找 target_func -> callers_in_deep1)
        '''
        all_callers = {}
        stack = list()
        processed_ids = set() # 已经处理了的CPG ID集合,用于防止重复分析
        deep1_callers = self.find_callers(method_cpg_node) # 第一层调用者
        for caller in deep1_callers:
            stack.append((1, caller))

        while stack:
            depth, cpg_node = stack.pop()
            if isinstance(cpg_node, dict) and NodeField.ID in cpg_node.keys() and depth <= call_max_depth:
                if cpg_node.get(NodeField.ID, None) not in processed_ids:
                    # 存储当前分析节点的信息
                    processed_ids.add(cpg_node.get(NodeField.ID, None))
                    if str(depth) not in all_callers.keys():
                        all_callers[str(depth)] = []
                    all_callers[str(depth)].append(cpg_node)
                    # 如果当前分析节点有调用点,就继续分析其调用点
                    temp_callers = self.find_callers(cpg_node)
                    if temp_callers:
                        for node in temp_callers:
                            stack.append((depth + 1, node)) # 此处深度加1
        return all_callers

    def find_method_call_argument_nodes_by_parameter_index(self, method_cpg_node: dict, parameter_index: int) -> List[dict]:
        '''
        查找上层的函数调用语句对应的实参节点
        '''
        method_call_argument_nodes = []
        if not isinstance(method_cpg_node, dict):
            return []

        # (1) 首先用Joern自带的callIn接口去找其直接调用的节点
        callin_cpg_nodes = self.find_callins(method_cpg_node)

        # (2) 然后根据函数名称去找到其他可能的函数调用点
        if not callin_cpg_nodes:
            call_sites = self.find_call_sites(method_cpg_node)
            callin_cpg_nodes.extend(call_sites)
            callin_cpg_nodes = self.remove_duplicate_nodes(callin_cpg_nodes)
        
        # (3) 对于每个函数调用节点,获取相应的实参节点
        for callin_cpg_node in callin_cpg_nodes:
            if parameter_index is not None:
                argument_nodes = self.find_method_call_arguments(callin_cpg_node)
                if isinstance(argument_nodes, list):
                    for argument_node in argument_nodes:
                        if isinstance(argument_node, dict) and argument_node.get(NodeField.ARGUMENT_INDEX, None) == parameter_index:
                            method_call_argument_nodes.append(argument_node)
            else:
                receiver_nodes = self.find_method_call_receivers(callin_cpg_node)
                method_call_argument_nodes.extend(receiver_nodes)
        
        method_call_argument_nodes = self.remove_duplicate_nodes(method_call_argument_nodes)
        
        return method_call_argument_nodes