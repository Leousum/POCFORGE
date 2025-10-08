import json

from joern_manager.stmt.stmt_type import StmtType
from joern_manager.stmt.control_structure import ControlStructure
from joern_manager.stmt.stmt_data import Obj, ObjField, Variable, Literal, Operation, Temporary
from joern_manager.stmt.stmts import Assign, CommonCall, ObjCall, Method, MethodReturn
from joern_manager.dataflow_processor import DataFlowProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class StmtProcessor(DataFlowProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level=0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def create_obj(self, cpg_node: dict):
        # 创建一个Obj
        obj = Obj(
            cpg_id = cpg_node.get(NodeField.ID, None),
            code = cpg_node[NodeField.CODE],
            class_type = cpg_node[NodeField.TYPE_FULL_NAME].replace(".<returnValue>", ""),
            identifier = cpg_node[NodeField.NAME]
        )
        return obj

    def create_variable(self, cpg_node: dict):
        # 创建一个Variable
        variable = Variable(
            cpg_id = cpg_node.get(NodeField.ID, None),
            code = cpg_node[NodeField.CODE],
            type = cpg_node[NodeField.TYPE_FULL_NAME].replace(".<returnValue>", ""),
            identifier = cpg_node[NodeField.NAME]
        )
        return variable
    
    def is_type_decl(self, cpg_node: dict):
        '''
        判断函数是否是class的定义函数
        '''
        # 首先根据函数名称来做简单的筛选
        if NodeField.CODE in cpg_node.keys():
            short_code = cpg_node[NodeField.CODE]
            if short_code.find("(") != -1 and short_code.find(")") != -1:
                short_code = short_code[:short_code.find("(")]
            if short_code.find("new ") != -1:
                return True
            elif short_code.find(".") != -1 or short_code.find("->") != -1:
                return False
        # 然后根据函数名称定义处做判断
        method_node = self.find_method_by_node_fullname(cpg_node)
        if method_node:
            if "isExternal" in method_node.keys():
                if str(method_node["isExternal"]).strip() == "false":
                    if "astParentType" in method_node.keys():
                        return (method_node["astParentType"].strip() == "TYPE_DECL")
        return False

    def _is_method_call(self, cpg_node: dict):
        '''
        判断一个CPG Node是否是函数调用
        '''
        if isinstance(cpg_node, dict) and NodeField.LABEL in cpg_node.keys() and NodeField.METHOD_FULL_NAME in cpg_node.keys():
            if cpg_node[NodeField.LABEL] == NodeLabel.CALL:
                if cpg_node[NodeField.METHOD_FULL_NAME].find("<operator>.") == -1:
                    if self.is_type_decl(cpg_node):
                        return False, None
                    elif self.is_obj_call(cpg_node):
                        return True, self.process_obj_call(cpg_node)
                    elif self.is_common_call(cpg_node):
                        return True, self.process_common_call(cpg_node)
        return False, None

    def process_identifier(self, cpg_node: dict):
        # 处理标识符
        type_name = cpg_node[NodeField.TYPE_FULL_NAME].replace(".<returnValue>", "")
        if type_name in self.variable_types:
            return self.create_variable(cpg_node)
        else:
            return self.create_obj(cpg_node)

    def process_obj_field(self, cpg_node: dict):
        # 处理对象属性
        obj_field = ObjField()
        obj_field.code = cpg_node[NodeField.CODE]
        obj_field.cpg_id = cpg_node.get(NodeField.ID, None)
        child_nodes = self.find_astChildren(cpg_node)
        for node in child_nodes:
            if node[NodeField.LABEL] == NodeLabel.IDENTIFIER:
                obj_field.obj = self.create_obj(node)
            elif node[NodeField.LABEL] == NodeLabel.FIELD_IDENTIFIER:
                obj_field.type = cpg_node[NodeField.TYPE_FULL_NAME].replace(".<returnValue>", "")
                obj_field.identifier = node[NodeField.CODE] # node[NodeField.NAME]
            elif node[NodeField.LABEL] == NodeOperator.FieldAccess: # TODO: 未来修复
                obj_field.obj = self.process_obj_field(node) # 处理 stu.classmate.name = "CCC"; 这种情况 
        obj_field.update_signature()
        return obj_field

    def process_literal(self, cpg_node: dict):
        # 处理字面量
        # TODO:目前只对 int,float,str,bool 4种类型进行了转换,未来可能需要处理更多类型
        node_type = cpg_node[NodeField.TYPE_FULL_NAME].replace(".<returnValue>", "")
        node_value = cpg_node[NodeField.CODE]
        if node_type.find("char[") != -1 and node_type.find("]") != -1:
            node_type = "char[]"
        if node_type in self.type_map.keys():
            if self.type_map[node_type] == "int":
                node_value = node_value.replace("//\n", "")
                node_value = int(node_value)
            elif self.type_map[node_type] == "float":
                node_value = node_value.replace("//\n", "")
                node_value = float(node_value)
            elif self.type_map[node_type] == "str":
                node_value = node_value.strip('\"').strip("\'").strip('"').strip("'")
                node_value = str(node_value)
            elif self.type_map[node_type] == "bool":
                if node_value.lower().find("true") != -1:
                    node_value = True
                elif node_value.lower().find("false") != -1:
                    node_value = False
                else:
                    node_value = bool(node_value)
        literal = Literal(
            type = node_type,
            value = node_value
        )
        return literal

    def process_operation(self, cpg_node: dict):
        # 处理数据操作
        operation = Operation()
        operation.code = cpg_node[NodeField.CODE]
        operation.cpg_id = cpg_node.get(NodeField.ID, None)
        operation.operator = cpg_node[NodeField.METHOD_FULL_NAME]
        child_nodes = self.find_astChildren(cpg_node)
        for node in child_nodes:
            operation.operands.append(self.parse_stmt(node))
        return operation
    
    def process_assignment(self, cpg_node: dict):
        # 处理赋值语句(已处理=, +=, .=, -=, *=, /=, %=等赋值运算)
        assign = Assign()
        assign.code = cpg_node[NodeField.CODE]
        assign.cpg_id = cpg_node.get(NodeField.ID, None)
        if cpg_node[NodeField.METHOD_FULL_NAME].strip() == NodeOperator.ASSIGNMENT:
            target_nodes = self.find_assign_targets(cpg_node)
            for node in target_nodes:
                target = self.parse_stmt(node)
                if target:
                    assign.LValues.append(target)
            source_node = self.find_assign_final_sources(cpg_node)
            assign.RValue = self.parse_stmt(source_node)
        else:
            operation = Operation()
            operation.code = cpg_node[NodeField.CODE]
            operation.cpg_id = cpg_node.get(NodeField.ID, None)
            operation.operator = cpg_node[NodeField.METHOD_FULL_NAME]
            child_nodes = self.find_astChildren(cpg_node)
            for i in range(0, len(child_nodes)):
                node = child_nodes[i]
                node_stmt = self.parse_stmt(node)
                operation.operands.append(node_stmt)
                if i == 0:
                    assign.LValues.append(node_stmt)
            assign.RValue = operation
        return assign

    def process_method(self, cpg_node: dict, obj: Obj):
        # 处理函数定义
        method = Method()
        if obj is not None:
            method.node_type = StmtType.OBJECT_METHOD
            method.obj_name = obj.class_type
        else:
            method.node_type = StmtType.COMMON_METHOD
        method.fullName = self.get_method_full_name(cpg_node)
        method.shortName = self.get_method_short_name(cpg_node)
        method.methodReturn = self.get_method_return_type(cpg_node)
        parameter_nodes = self.find_method_parameters(cpg_node)
        for node in parameter_nodes:
            method.parameter_types.append(node[NodeField.TYPE_FULL_NAME])
            parameter_index1 = node[NodeField.NAME]
            parameter_index2 = str(node[NodeField.INDEX])
            parameter = self.parse_stmt(node)
            if parameter is not None:
                method.parameters[parameter_index1] = parameter
                method.parameters[parameter_index2] = parameter
        method.update_signature()
        return method

    def process_obj_call(self, cpg_node: dict):
        # 处理类的函数调用
        obj_call = ObjCall()
        obj_call.code = cpg_node[NodeField.CODE]
        obj_call.cpg_id = cpg_node.get(NodeField.ID, None)
        obj_call.fullName = self.get_method_full_name(cpg_node)
        argument_nodes = self.find_method_call_arguments(cpg_node)
        for node in argument_nodes:
            if str(node[NodeField.ARGUMENT_INDEX]) == "0":
                obj_call.obj = self.create_obj(node)
                obj_call.arguments["0"] = obj_call.obj
            else:
                argument_index = node[NodeField.ARGUMENT_INDEX]
                if argument_index == "-1" and NodeField.ARGUMENT_NAME in node.keys():
                    argument_index = node[NodeField.ARGUMENT_NAME]
                argument = self.parse_stmt(node)
                obj_call.arguments[str(argument_index)] = argument
        obj_call.method = self.process_method(cpg_node, obj_call.obj)
        return obj_call

    def process_common_call(self, cpg_node: dict):
        # 处理普通函数调用
        common_call = CommonCall()
        common_call.code = cpg_node.get(NodeField.CODE, None)
        common_call.cpg_id = cpg_node.get(NodeField.ID, None)
        common_call.fullName = self.get_method_full_name(cpg_node)
        argument_nodes = self.find_method_call_arguments(cpg_node)
        for node in argument_nodes:
            argument_index = node[NodeField.ARGUMENT_INDEX]
            if argument_index == "-1" and NodeField.ARGUMENT_NAME in node.keys():
                argument_index = node[NodeField.ARGUMENT_NAME]
            argument = self.parse_stmt(node)
            common_call.arguments[str(argument_index)] = argument
        common_call.method = self.process_method(cpg_node, None)
        return common_call

    def process_control_structure(self, cpg_node: dict):
        # 处理控制结构
        controlstructure = ControlStructure()
        controlstructure.cpg_id = cpg_node.get(NodeField.ID, None)
        controlstructure.code = cpg_node[NodeField.CODE]
        controlstructure.controlStructureType = cpg_node[NodeField.CONTROL_STRUCTURE_TYPE]
        controlstructure.condition = self.parse_stmt(self.find_control_condition(cpg_node))
        return controlstructure

    def process_method_return(self, cpg_node: dict):
        # 处理函数返回值语句
        method_return = MethodReturn()
        method_return.cpg_id = cpg_node.get(NodeField.ID, None)
        method_return.code = cpg_node[NodeField.CODE]
        cfgin_nodes = self.find_cfgIn(cpg_node)
        if cfgin_nodes:
            method_return.return_result = self.parse_stmt(cfgin_nodes[0])
        return method_return
    
    def process_type_cast(self, cpg_node: dict):
        # 处理强制类型转换语句
        temporary = Temporary()
        if isinstance(cpg_node, dict) and NodeField.TYPE_FULL_NAME in cpg_node.keys():
            temporary.type = cpg_node[NodeField.TYPE_FULL_NAME]
            if temporary.type is not None:
                if temporary.type in self.type_map.keys():
                    temporary.type = self.type_map[temporary.type]
        return temporary

    def parse_stmt(self, cpg_node: dict):
        # 处理子节点,将其转换为对应的类
        temp_id = None
        temp_code = None
        if isinstance(cpg_node, dict):
            if NodeField.ID in cpg_node.keys():
                temp_id = cpg_node.get(NodeField.ID, None)
            if NodeField.CODE in cpg_node.keys():
                temp_code = cpg_node[NodeField.CODE]
        # self.log_manager.log_info(f"Parsing CPG Node to Stmt: [cpg id:{temp_id}] [code:{temp_code}]", False, self.indent_level)
        if cpg_node:
            # 记录typeFullName TODO:记录此信息是为区分标识符的类型,还需要人工分析(当我们认为已经记录了所有类型后,可以删除此处代码)
            if isinstance(cpg_node, dict):
                if NodeField.TYPE_FULL_NAME in cpg_node.keys():
                    if cpg_node[NodeField.TYPE_FULL_NAME] not in self.all_types:
                        self.all_types.append(cpg_node[NodeField.TYPE_FULL_NAME])
                        with open(self.all_types_path, "w", encoding = "utf-8") as f:
                            json.dump(self.all_types, f, ensure_ascii = False, indent = 4)
            if cpg_node[NodeField.LABEL] == NodeLabel.CALL:
                if cpg_node[NodeField.METHOD_FULL_NAME].find("<operator>.") != -1:
                    if cpg_node[NodeField.METHOD_FULL_NAME].strip().find(NodeOperator.ASSIGNMENT) != -1:
                        return self.process_assignment(cpg_node)
                    elif cpg_node[NodeField.METHOD_FULL_NAME].strip() == NodeOperator.FieldAccess:
                        return self.process_obj_field(cpg_node)
                    elif cpg_node[NodeField.METHOD_FULL_NAME].strip() == NodeOperator.ALLOC:
                        if cpg_node[NodeField.TYPE_FULL_NAME] in self.variable_types:
                            return self.process_literal(cpg_node)
                        else:
                            return self.create_obj(cpg_node) # TODO:这里具体应该采用什么方法还不确定!
                    else:
                        return self.process_operation(cpg_node)
                elif self.is_type_decl(cpg_node):
                    return self.create_obj(cpg_node)
                elif self.is_obj_call(cpg_node):
                    return self.process_obj_call(cpg_node)
                elif self.is_common_call(cpg_node):
                    return self.process_common_call(cpg_node)
            elif cpg_node[NodeField.LABEL] == NodeLabel.LITERAL:
                return self.process_literal(cpg_node)
            elif cpg_node[NodeField.LABEL] in [NodeLabel.IDENTIFIER, NodeLabel.METHOD_PARAMETER_IN]:
                return self.process_identifier(cpg_node)
            elif cpg_node[NodeField.LABEL] == NodeLabel.CONTROL_STRUCTURE:
                return self.process_control_structure(cpg_node)
            elif cpg_node[NodeField.LABEL] == NodeLabel.RETURN:
                return self.process_method_return(cpg_node)
            elif cpg_node[NodeField.LABEL] == NodeLabel.TYPE_REF:
                return self.process_type_cast(cpg_node)
        return None

    def _get_node_by_variable(self, cpg_node: dict, variable_name: str):
        '''
        迭代分析AST子节点,找到指定变量对应的CPG节点
        '''
        if isinstance(cpg_node, dict) and isinstance(variable_name, str):
            stmt = self.parse_stmt(cpg_node)
            if stmt is not None:
                if stmt.node_type in ["Literal", "Temporary"]:
                    # 字面量/临时量无需处理
                    return None, False
                elif stmt.node_type in ["Variable", "Object", "Object_Field"]:
                    # 变量/对象/对象字段的标识符等于variable_name时,认为找到了所需的CPG节点
                    if stmt.identifier in [variable_name, "this." + variable_name, "this->variable_name", "self." + variable_name]:
                        return cpg_node, True
                else:
                    # 其他类型的语句需要展开分析
                    ast_children_nodes = self.find_astChildren(cpg_node)
                    for children_node in ast_children_nodes:
                        node, success_find_node = self._get_node_by_variable(children_node, variable_name)
                        if success_find_node:
                            return node, True
        return None, False