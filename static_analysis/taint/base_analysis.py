import os
import json
import copy
import sys
import shutil
static_analysis_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
autopoc_path = os.path.abspath(os.path.join(static_analysis_path, ".."))
sys.path.append(autopoc_path)
sys.path.append(static_analysis_path)

from pfg.pointer_flow_graph import PFGNode
from pfg.pointer_flow_graph import PointerFlowGraph
from joern_manager.stmt.control_structure import ControlStructure
from joern_manager.stmt.stmts import Assign, CommonCall, ObjCall, Method, MethodReturn
from joern_manager.stmt.stmt_data import Obj, ObjField, Variable, Literal, Operation
from joern_manager.joern import JoernServer
from front_page.front_page_manager import PageManager
from LLM.model_manager import ModelManager
from utils.log_manager import LogManager
from static_analysis.taint.functions import process_func
from static_analysis.taint.payload_manager import PayloadManager
from static_analysis.taint.code_manager import CodeManager
from static_analysis.taint.source_sink_handler import SourceSinkHandler
from ...joern_manager.cpg_field import NodeType,NodeField,NodeConstraint,NodeMethod,NodeLabel,NodeOperator

class BaseAnalyzer():
    def __init__(self, config_file, joern_server: JoernServer, page_manager: PageManager, model_manager: ModelManager, log_manager: LogManager, s2_handler = None) -> None:
        self.config_file = config_file
        self.joern_server = joern_server
        self.page_manager = page_manager
        self.model_manager = model_manager
        self.log_manager = log_manager
        self.payload_manager = PayloadManager(model_manager)
        self.code_manager = CodeManager(joern_server, log_manager)
        self.analysis_num = dict() # 各个节点被分析次数(必须保留)
        self.next_stmt_map = dict() # 函数调用语句的下一条语句映射关系(key是cpg_id,value是call stmt)
        self.block_parent_block_map = dict() # 一个节点和其所属父节点CPG ID的映射关系
        self.operator_map_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "cpgql", "operator_map.json")
        self.taint_config_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "taint_config.json")
        self.vuln_keywords_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "potential_vuln_keywords.json")
        self.taint_config = None
        self.vuln_keywords = dict()
        self.redirect_urls = list()
        self.conditions = list()
        self.global_vars = dict()
        with open(self.taint_config_path, "r", encoding = "utf-8") as f:
            self.taint_config = json.load(f)
        with open(self.vuln_keywords_path, "r", encoding = "utf-8") as f:
            self.vuln_keywords = json.load(f)
        self.interest_flag = False # 当前分析语句是否是感兴趣的一个语句
        self.worklist = list() # 工作列表(栈)
        self.global_PFG_map = dict() # CPG ID和PFG图的映射字典
        self.s2_handler = s2_handler
        self.source_vars = list()
        self.source_funcs = list()
        self.sinks = list()
        self.redirects = list()
        self.at_first = True
        if s2_handler is not None:
            self.source_vars, self.source_funcs = self.s2_handler.get_separate_sources()
            self.sinks = self.s2_handler.get_sinks()
            self.redirects = self.s2_handler.get_redirects()

    def at_fixpoint(self, code_block_id, cpg_id, PFG_in: PointerFlowGraph, stmt_source: str):
        code_id = stmt_source + "_" + str(code_block_id) + "_" + str(cpg_id)
        # 检查当前处理语句是否到达了不动点(如果到达不动点,则无意义进行后续计算)
        if code_id not in self.analysis_num.keys():
            self.analysis_num[code_id] = 0
        self.analysis_num[code_id] += 1
        # 设置分析次数上限
        if self.analysis_num[code_id] > 50:
            return True
        # 为了减小空间消耗,只会记录那些反复执行的语句的PFG映射关系
        if self.analysis_num[code_id] == 1:
            return False
        if self.analysis_num[code_id] == 2:
            if code_id not in self.global_PFG_map.keys():
                PFG = copy.deepcopy(PFG_in)
                self.global_PFG_map[code_id] = PFG
            return False
        elif self.analysis_num[code_id] > 2:
            if code_id in self.global_PFG_map.keys():
                if self.global_PFG_map[code_id] is not None:
                    PFG_old = self.global_PFG_map[code_id]
                    # 若两个PFG存在差异,就认为未到达不动点,且这时候需要更新全局PFG
                    if PFG_in.is_different(PFG_old):
                        PFG = copy.deepcopy(PFG_in)
                        self.global_PFG_map[code_id] = PFG
                        return False
            PFG = copy.deepcopy(PFG_in)
            self.global_PFG_map[code_id] = PFG
        self.log_manager.log_info(f'[namespace: {code_block_id}] [cpg id: {cpg_id}] reached the fix point!', False, 3)
        return True

# ======================================== Operation Process Start ========================================
    def update_value_taint(self, pfg_node: PFGNode, PFG: PointerFlowGraph):
        # 根据PFG更新节点的value和is_taint
        taint_status = False
        pfg_node_value = None
        if pfg_node.signature in PFG.signature2id.keys():
            id = PFG.signature2id[pfg_node.signature]
            if id <= (len(PFG.nodes) - 1) and id >= 0:
                taint_status = PFG.nodes[id].is_taint
                pfg_node_value = PFG.nodes[id].value
        if pfg_node_value is None:
            if pfg_node.node_type in ["Object_Field", "Index"]:
                for node in PFG.find_nodes_by_short_signature(pfg_node):
                    if node.value is not None:
                        if PFG.is_actual_same(pfg_node, node):
                            taint_status = node.is_taint
                            pfg_node_value = node.value
                            break
        pfg_node.is_taint = taint_status
        pfg_node.value = pfg_node_value
        self.log_manager.log_info(f'{pfg_node.to_string()}', False, 3)
    
    def update_operator_map(self, operator: str):
        # 更新操作符字典
        operator_map = dict()
        with open(self.operator_map_path, "r", encoding = "utf-8") as f1:
            operator_map = json.load(f1)
        if operator:
            if operator not in operator_map.keys():
                operator_map[operator] = "unkown"
                with open(self.operator_map_path, "w", encoding = "utf-8") as f2:
                    json.dump(operator_map, f2, ensure_ascii = False, indent = 4)

    def check_concat_operands(self, operand: PFGNode):
        # 检查一个操作数中是否含有潜在漏洞关键字
        vuln_type = self.log_manager.vuln_type
        if vuln_type in self.vuln_keywords.keys():
            if not operand.is_taint:
                for keyword in self.vuln_keywords[vuln_type]:
                    if str(operand.value).find(keyword) != -1:
                        return True
        return False

    def cut_num_from_str(self, text: str):
        # 截取字符串中前一部分的数字
        if text is None:
            return "0"
        num = ""
        for item in text:
            if item in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "."]:
                num += item
            else:
                break
        num = num.strip(".")
        if num == "":
            num = "0"
        return num

    def calculate_operation(self, operands: list, operator: str):
        # operands: 操作数列表,其中每个元素都是一个PFG Node
        # operator: 操作符号
        # return: PFG Temporary Node
        result_pfg_node = PFGNode(node_type = "Temporary")
        try:
            for operand in operands:
                if operand is None:
                    return result_pfg_node
                elif operand.own_type is not None:
                    result_pfg_node.own_type = operand.own_type
            if operator == "encaps":
                result_pfg_node.value = ""
                for operand in operands:
                    if operand.value is not None:
                        result_pfg_node.value += str(operand.value)
            else:
                if len(operands) == 1:
                    if operands[0].value is not None:
                        if operator == NodeOperator.MINUX:
                            result_pfg_node.value = (-operands[0].value)
                        elif operator == NodeOperator.NOT:
                            result_pfg_node.value = (not operands[0].value)
                        elif operator == NodeOperator.LOGIC_NOT:
                            result_pfg_node.value = (not operands[0].value)
                        elif operator == NodeOperator.POST_INCREMENT:
                            result_pfg_node.value = (operands[0].value + 1)
                        elif operator == NodeOperator.POST_DECREMENT:
                            result_pfg_node.value = (operands[0].value - 1)
                        elif operator == NodeOperator.PRE_INCREMENT:
                            result_pfg_node.value = (operands[0].value + 1)
                        elif operator == NodeOperator.PRE_DECREMENT:
                            result_pfg_node.value = (operands[0].value - 1)
                        elif operator == "no_operator": # TODO:暂时不能很好地判断非None
                            result_pfg_node.value = bool(operands[0].value)
                        else:
                            self.update_operator_map(operator)
                elif len(operands) == 2:
                    if (operands[0].value is not None and operands[1].value is not None) or operator == NodeOperator.CAST:
                        # 处理类型不一致的变量比较问题
                        if operator in [NodeOperator.LESS_THAN, NodeOperator.GREATER_THAN, NodeOperator.LESS_EQUALS_THAN, NodeOperator.GREATER_EQUALS_THAN]:
                            if isinstance(operands[0].value, int) and isinstance(operands[1].value, str):
                                operands[1].value = int(self.cut_num_from_str(operands[1].value))
                            elif isinstance(operands[1].value, int) and isinstance(operands[0].value, str):
                                operands[0].value = int(self.cut_num_from_str(operands[0].value))
                            elif isinstance(operands[0].value, float) and isinstance(operands[1].value, str):
                                operands[1].value = float(self.cut_num_from_str(operands[1].value))
                            elif isinstance(operands[1].value, float) and isinstance(operands[0].value, str):
                                operands[0].value = float(self.cut_num_from_str(operands[0].value))
                        if operator in [NodeOperator.ADDITION, NodeOperator.ASSIGNMENT_PLUS, NodeOperator.CONCAT, NodeOperator.ASSIGNMENT_CONCAT, NodeOperator.PLUS]:
                            if isinstance(operands[0].value, str) or isinstance(operands[1].value, str):
                                result_pfg_node.value = str(operands[0].value) + str(operands[1].value)
                                if operands[0].is_taint or operands[1].is_taint:
                                    if (operands[0].is_taint and operands[1].is_taint) or self.check_concat_operands(operands[0]) or self.check_concat_operands(operands[1]):
                                        # TODO: 需要观察有没有两个变量同时被污染的情况
                                        # self.interest_flag = True TODO:这里是认为一些感兴趣操作需要被记录下来
                                        self.code_manager._record_interest_operation(operator, operands[0], operands[1])
                            else:
                                result_pfg_node.value = (operands[0].value + operands[1].value)
                        elif operator == NodeOperator.ASSIGNMENT_MINUS:
                            result_pfg_node.value = (operands[0].value - operands[1].value)
                        elif operator == NodeOperator.ASSIGNMENT_MULTIPLICATION:
                            result_pfg_node.value = (operands[0].value * operands[1].value)
                        elif operator == NodeOperator.ASSIGNMENT_DIVISION:
                            result_pfg_node.value = (operands[0].value / operands[1].value)
                        elif operator == NodeOperator.ASSIGNMENT_MODULO:
                            result_pfg_node.value = (operands[0].value % operands[1].value)
                        elif operator == NodeOperator.SUBTRACTION:
                            result_pfg_node.value = (operands[0].value - operands[1].value)
                        elif operator == NodeOperator.MULTIPLICATION:
                            result_pfg_node.value = (operands[0].value * operands[1].value)
                        elif operator == NodeOperator.DIVISION:
                            result_pfg_node.value = (operands[0].value / operands[1].value)
                        elif operator == NodeOperator.FLOOR_DIV:
                            result_pfg_node.value = (operands[0].value // operands[1].value)
                        elif operator == NodeOperator.MODULO:
                            result_pfg_node.value = (operands[0].value % operands[1].value)
                        elif operator == NodeOperator.EXPONENTIATION:
                            result_pfg_node.value = (operands[0].value ** operands[1].value)
                        elif operator == NodeOperator.AND:
                            result_pfg_node.value = (operands[0].value & operands[1].value)
                        elif operator == NodeOperator.OR:
                            result_pfg_node.value = (operands[0].value | operands[1].value)
                        elif operator == NodeOperator.XOR:
                            result_pfg_node.value = (operands[0].value ^ operands[1].value)
                        elif operator == NodeOperator.LOGIC_AND:
                            result_pfg_node.value = (operands[0].value and operands[1].value)
                        elif operator == NodeOperator.LOGIC_OR:
                            result_pfg_node.value = (operands[0].value or operands[1].value)
                        elif operator == NodeOperator.EQUALS:
                            result_pfg_node.value = (operands[0].value == operands[1].value)
                        elif operator == NodeOperator.NOT_EQUALS:
                            result_pfg_node.value = (operands[0].value != operands[1].value)
                        elif operator == NodeOperator.LESS_THAN:
                            result_pfg_node.value = (operands[0].value < operands[1].value)
                        elif operator == NodeOperator.GREATER_THAN:
                            result_pfg_node.value = (operands[0].value > operands[1].value)
                        elif operator == NodeOperator.LESS_EQUALS_THAN:
                            result_pfg_node.value = (operands[0].value <= operands[1].value)
                        elif operator == NodeOperator.GREATER_EQUALS_THAN:
                            result_pfg_node.value = (operands[0].value >= operands[1].value)
                        elif operator == NodeOperator.SHIFT_LEFT:
                            result_pfg_node.value = (operands[0].value << operands[1].value)
                        elif operator == NodeOperator.ARITHMETIC_SHIFT_RIGHT:
                            result_pfg_node.value = (operands[0].value >> operands[1].value)
                        elif operator == NodeOperator.COALESCE:
                            result_pfg_node.value = operands[0].value if (operands[0].value is not None) else operands[1].value
                        elif operator == NodeOperator.CAST:
                            type_operand = None
                            operated_operand = None
                            if operands[0].node_type == "Temporary":
                                type_operand = operands[0]
                                operated_operand = operands[1]
                            elif operands[1].node_type == "Temporary":
                                type_operand = operands[1]
                                operated_operand = operands[0]
                            if type_operand is not None and operated_operand is not None and type_operand.own_type is not None:
                                if operated_operand.value is not None:
                                    num = None
                                    if isinstance(operated_operand.value, str):
                                        num = self.cut_num_from_str(operated_operand.value)
                                    if type_operand.own_type == "int" and num is not None:
                                        result_pfg_node.value = int(num)
                                    elif type_operand.own_type == "float" and num is not None:
                                        result_pfg_node.value = float(num)
                                    elif type_operand.own_type == "str":
                                        result_pfg_node.value = str(operated_operand.value)
                                    elif type_operand.own_type == "bool":
                                        result_pfg_node.value = bool(operated_operand.value)
                        else:
                            self.update_operator_map(operator)
                    else:
                        if operator == NodeOperator.COALESCE:
                            result_pfg_node.value = operands[0].value if (operands[0].value is not None) else operands[1].value
                        else:
                            self.update_operator_map(operator)
                elif len(operands) == 3:
                    if operands[0].value is not None:
                        if operator == NodeOperator.CONDITIONAL:
                            if operands[0].value:
                                result_pfg_node.value = operands[1].value
                            else:
                                result_pfg_node.value = operands[2].value
                        else:
                            self.update_operator_map(operator)
        except:
            pass
        return result_pfg_node
 
# ======================================== Operation Functions End ========================================

# ======================================== Data Process Start ========================================
    def create_obj_pfg_node(self, stmt_data: Obj, PFG: PointerFlowGraph, code_block_id):
        pfg_node = None
        if stmt_data is not None:
            pfg_node = PFGNode(
                code_block_id = code_block_id,
                node_type = "Object",
                parent_type = None,
                own_type = stmt_data.class_type,
                identifier = stmt_data.identifier,
                value = None,
                is_class = True
                )
        self.update_value_taint(pfg_node, PFG)
        return pfg_node
    
    def create_obj_field_pfg_node(self, stmt_data: ObjField, PFG: PointerFlowGraph, code_block_id):
        pfg_node = None
        if stmt_data is not None:
            pfg_node = PFGNode(
                code_block_id = code_block_id,
                node_type = "Object_Field",
                parent_type = stmt_data.obj.class_type if (stmt_data.obj is not None) else None,
                parent_identifier = stmt_data.obj.identifier if (stmt_data.obj is not None) else None,
                own_type = stmt_data.type,
                identifier = stmt_data.identifier,
                value = stmt_data.value,
                is_class = False
                )
        self.update_value_taint(pfg_node, PFG)
        return pfg_node
    
    def create_variable_pfg_node(self, stmt_data: Variable, PFG: PointerFlowGraph, code_block_id):
        pfg_node = None
        if stmt_data is not None:
            pfg_node = PFGNode(
                code_block_id = code_block_id,
                node_type = "Variable",
                parent_type = None,
                own_type = stmt_data.type,
                identifier = stmt_data.identifier,
                value = stmt_data.value,
                is_class = False
                )
        self.update_value_taint(pfg_node, PFG)
        return pfg_node
    
    def create_index_pfg_node(self, operated_pfg_node: PFGNode, operand_stmt, PFG: PointerFlowGraph, code_block_id):
        pfg_node = None
        if operand_stmt is not None:
            if operand_stmt.node_type in ["CommonCall", "ObjCall"]:
                return None
            pfg_node = PFGNode(
                code_block_id = code_block_id,
                node_type = "Index",
                parent_type = operated_pfg_node.own_type if (operated_pfg_node is not None) else None,
                parent_identifier = operated_pfg_node.identifier if (operated_pfg_node is not None) else None,
                own_type = None,
                identifier = None,
                value = None,
                is_class = False
            )
            if operand_stmt.node_type == "Object":
                pfg_node.own_type = operand_stmt.class_type
            else:
                pfg_node.own_type = operand_stmt.type
                pfg_node.identifier = operand_stmt.value
            if operand_stmt.node_type == "Operation":
                pfg_node.identifier = operand_stmt.code
            pfg_node.update_signature()
            self.update_value_taint(pfg_node, PFG)
        return pfg_node
    
    def create_literal_pfg_node(self, stmt_data: Literal, code_block_id):
        pfg_node = None
        if stmt_data is not None:
            pfg_node = PFGNode(
                code_block_id = code_block_id,
                node_type = "Literal",
                parent_type = None,
                own_type = stmt_data.type,
                identifier = stmt_data.value,
                value = stmt_data.value,
                is_class = False
                )
        return pfg_node
    
    def create_php_array_pfg_node(self, stmt_data: Obj, PFG: PointerFlowGraph, code_block_id):
        pfg_node = self.process_stmt_data(stmt_data.oneself, code_block_id, PFG, {"nodes": [], "field_edges": []})
        if pfg_node is not None:
            for item in stmt_data.array_items:
                if isinstance(item, dict) and "index" in item.keys() and "value" in item.keys():
                    index_pfg_node = self.process_stmt_data(item["index"], code_block_id, PFG, {"nodes": [], "field_edges": []})
                    value_pfg_node = self.process_stmt_data(item["value"], code_block_id, PFG, {"nodes": [], "field_edges": []})
                    if index_pfg_node is not None and value_pfg_node is not None:
                        pfg_node.attributes.append({"index": index_pfg_node, "value": value_pfg_node, "index_stmt": item["index"], "value_stmt": item["value"]})
        return pfg_node
    
    def is_php_global_var(self, identifier):
        # 判断一个标识符是否是PHP中的全局变量标识符(未来可拆分)
        global_vars = self.taint_config["sources"]["php_global_vars"]
        if identifier:
            for global_var in global_vars:
                if identifier.find(global_var) != -1:
                    return True
        return False

    def is_global_var(self, stmt_data):
        # 判断一个变量是否是全局变量
        var = None
        is_global = False
        try:
            if stmt_data is not None:
                if hasattr(stmt_data, 'code'):
                    var = stmt_data.code
                if var is None and hasattr(stmt_data, 'identifier'):
                    var = stmt_data.identifier
                if var in self.global_vars.keys():
                    is_global = True
                else:
                    if stmt_data.node_type == "Operation":
                        if stmt_data.operator == NodeOperator.IndexAccess:
                            is_global = self.is_php_global_var(var)
                    elif stmt_data.node_type == "Object":
                        if var is not None:
                            if var.find("<global>") != -1:
                                is_global = True
                    elif stmt_data.node_type == "Object_Field":
                        if var is not None:
                            if not (var.startswith("__") and var.endswith("__")):
                                if stmt_data.obj is not None:
                                    is_global = self.is_global_var(stmt_data.obj)
                    elif stmt_data.node_type == "Literal":
                        if var is not None and isinstance(var, str):
                            is_global = var.isupper() # 处理PHP的全局变量
        except:
            is_global = False
        if is_global and var is not None:
            if var not in self.global_vars.keys():
                self.global_vars[var] = dict()
                self.global_vars[var]["own_type"] = None
                self.global_vars[var]["value"] = None
                self.global_vars[var]["process_num"] = 0
        return is_global
    
    def is_var(self, data: dict):
        # 判断字典是否是变量
        if isinstance(data, dict):
            if "node_type" in data.keys():
                if data["node_type"] in ["Variable", "Object_Field"]:
                    return True
                elif data["node_type"] == "Operation":
                    if "operator" in data.keys():
                        if data["operator"] == NodeOperator.IndexAccess:
                            return True
        return False

    def process_define_var(self, pfg_node: PFGNode, stmt_data: ObjField, code_block_id, PFG):
        # 处理PHP使用define语句定义的全局变量
        if stmt_data is not None:
            if stmt_data.node_type == "Object_Field":
                var = stmt_data.code if stmt_data.code is not None else stmt_data.identifier
                if var is not None and isinstance(var, str):
                    not_processed = True
                    if var in self.global_vars.keys():
                        if self.global_vars[var]["own_type"] is not None or self.global_vars[var]["value"] is not None:
                            pfg_node.own_type = self.global_vars[var]["own_type"]
                            pfg_node.value = self.global_vars[var]["value"]
                            not_processed = False
                    if not_processed:
                        if var not in self.global_vars.keys():
                            self.global_vars[var] = dict()
                            self.global_vars[var]["own_type"] = None
                            self.global_vars[var]["value"] = None
                            self.global_vars[var]["process_num"] = 0
                        if self.global_vars[var]["process_num"] <= 2:
                            self.global_vars[var]["process_num"] += 1
                            start_with_define_node = self.joern_server.find_node_startwith("define", var)
                            if start_with_define_node is not None and isinstance(start_with_define_node, dict):
                                define_cpg_node = self.joern_server.find_define_node(start_with_define_node)
                                if define_cpg_node is not None and isinstance(define_cpg_node, dict):
                                    if NodeField.ID in define_cpg_node.keys():
                                        if define_cpg_node[{NodeField.ID}] != stmt_data.cpg_id:
                                            define_stmt = self.joern_server.parse_stmt(define_cpg_node)
                                            define_pfg_node = self.process_stmt_data(define_stmt, code_block_id, PFG, {"nodes": [], "field_edges": []}, ignore_none = True)
                                            if define_pfg_node is not None:
                                                pfg_node.own_type = define_pfg_node.own_type
                                                pfg_node.value = define_pfg_node.value
                                                self.global_vars[var]["own_type"] = define_pfg_node.own_type
                                                self.global_vars[var]["value"] = define_pfg_node.value

    def process_stmt_data(self, stmt_data, code_block_id, PFG: PointerFlowGraph, node_map: dict, ignore_none = False, add_node_flag = False, is_global = False):
        # 处理数据,将其转换为指针流图的节点,并建立PFG中的属性边
        pfg_node = PFGNode(node_type = "Temporary")
        if stmt_data is not None:
            # 判断是否是全局变量
            if not is_global:
                is_global = self.is_global_var(stmt_data)
            # 根据Stmt类型构建相应的PFG Node对象
            if stmt_data.node_type == "Object":
                pfg_node = self.create_obj_pfg_node(stmt_data, PFG, code_block_id)
                node_map["nodes"].append({"pfg_node": pfg_node, "stmt": stmt_data})
            elif stmt_data.node_type == "Object_Field":
                obj_node = self.process_stmt_data(stmt_data.obj, code_block_id, PFG, node_map, is_global = is_global)
                pfg_node = self.create_obj_field_pfg_node(stmt_data, PFG, code_block_id)
                if obj_node is not None:
                    if obj_node.own_type is not None:
                        pfg_node.parent_type = obj_node.own_type
                if is_global:
                    self.process_define_var(pfg_node, stmt_data, code_block_id, PFG)
                node_map["nodes"].append({"pfg_node": obj_node, "stmt": stmt_data.obj})
                node_map["nodes"].append({"pfg_node": pfg_node, "stmt": stmt_data})
                node_map["field_edges"].append({"start": obj_node, "end": pfg_node})
            elif stmt_data.node_type == "Variable":
                pfg_node = self.create_variable_pfg_node(stmt_data, PFG, code_block_id)
                node_map["nodes"].append({"pfg_node": pfg_node, "stmt": stmt_data})
            elif stmt_data.node_type == "Literal":
                pfg_node = self.create_literal_pfg_node(stmt_data, code_block_id)
            elif stmt_data.node_type == "Operation":
                if stmt_data.operator == NodeOperator.IndexAccess:
                    operated_stmt = None
                    operand_stmt = None
                    operated_pfg_node = None
                    for i in range(len(stmt_data.operands)):
                        operand = stmt_data.operands[i]
                        if i == 0:
                            operated_stmt = copy.deepcopy(operand)
                            operated_pfg_node = self.process_stmt_data(operand, code_block_id, PFG, node_map, is_global = is_global)
                        elif i == 1:
                            operand_stmt = copy.deepcopy(operand)
                            pfg_node = self.create_index_pfg_node(operated_pfg_node, operand, PFG, code_block_id)
                    node_map["nodes"].append({"pfg_node": operated_pfg_node, "stmt": operated_stmt})
                    node_map["nodes"].append({"pfg_node": pfg_node, "stmt": stmt_data}) # TODO: 思考这里应该填stmt_data还是operand_stmt
                    node_map["field_edges"].append({"start": operated_pfg_node, "end": pfg_node})
                else:
                    pfg_nodes = list()
                    for operand in stmt_data.operands:
                        pfg_nodes.append(self.process_stmt_data(operand, code_block_id, PFG, node_map, ignore_none, add_node_flag = True, is_global = is_global))
                    add_node_flag = False
                    if ignore_none: # TODO:思考or stmt_data.operator in ["<operator>.addition", "<operator>.assignmentPlus", "<operator>.concat", "<operator>.assignmentConcat"]
                        for i in range(0, len(pfg_nodes)):
                            if pfg_nodes[i].value is None:
                                pfg_nodes[i].value = ""
                    self.log_manager.log_info(f'Calculate Operation: {stmt_data.code} {stmt_data.operator}', False, self.joern_server.log_level)
                    self.log_manager.log_info(f'Operands: ', False, self.joern_server.log_level)
                    for temp_node in pfg_nodes:
                        if temp_node is not None:
                            self.log_manager.log_info(f'{temp_node.signature}: {temp_node.value} (type: {type(temp_node.value)})', False, self.joern_server.log_level + 1)
                    pfg_node = self.calculate_operation(pfg_nodes, stmt_data.operator)
                    self.log_manager.log_info(f'Calculate Operation Result: {pfg_node.value} (type: {type(pfg_node.value)})', False, self.joern_server.log_level)
                    # 认为强制类型转换能够有效清理污点
                    if stmt_data == NodeOperator.CAST:
                        pfg_node.is_taint = False
                    # 对于自增等会改变自身属性的操作,需要将这类数据记录下来
                    if stmt_data.operator in [NodeOperator.POST_INCREMENT,NodeOperator.POST_DECREMENT,NodeOperator.PRE_INCREMENT,NodeOperator.PRE_DECREMENT]:
                        if pfg_nodes:
                            operated_pfg_node = pfg_nodes[0]
                            if self.need_add(operated_pfg_node):
                                operated_pfg_node.value = pfg_node.value
                                PFG.add_node(node = operated_pfg_node)
                    # 只要操作数中有一个被污染了,就认为整个数据操作都被污染
                    for node in pfg_nodes:
                        if node is not None:
                            if node.is_taint and stmt_data.operator != NodeOperator.CAST:
                                pfg_node.is_taint = True
                                break
            elif stmt_data.node_type in ["ObjCall", "CommonCall"]:
                if stmt_data.cpg_id in PFG.call_return.keys():
                    pfg_node = PFG.call_return[stmt_data.cpg_id]
            elif stmt_data.node_type == "MethodReturn":
                return_stmt = stmt_data.return_result
                pfg_node = self.process_stmt_data(return_stmt, code_block_id, PFG, node_map, ignore_none, add_node_flag = True)
            elif stmt_data.node_type == "Temporary":
                pfg_node.own_type = stmt_data.type
            elif stmt_data.node_type == "PHPArray":
                pfg_node = self.create_php_array_pfg_node(stmt_data, PFG, code_block_id)
            if add_node_flag:
                # 添加节点,创建属性边
                for Node in node_map["nodes"]:
                    if self.need_add(Node["pfg_node"]):
                        PFG.add_node(node = Node["pfg_node"], stmt = Node["stmt"])
                for field_edge in node_map["field_edges"]:
                    if self.need_add(field_edge["start"]) and self.need_add(field_edge["end"]):
                        PFG.add_field_edge(field_edge["start"], field_edge["end"])
                # 更新节点的value
                for Node in node_map["nodes"]:
                    if self.need_add(Node["pfg_node"]):
                        self.update_value_taint(Node["pfg_node"], PFG)
                        PFG.add_node(node = Node["pfg_node"], stmt = Node["stmt"])
            if pfg_node is not None:
                if pfg_node.node_type != "Temporary":
                    if is_global:
                        pfg_node.code_block_id = 0
                    pfg_node.update_signature()
        return pfg_node
# ======================================== Data Process End ========================================
    
# ======================================== Assignment Process Start ========================================
    
    def need_add(self, pfg_node: PFGNode):
        # 判断节点是否需要放入到指针流图中
        if pfg_node is None:
            return False
        if pfg_node.node_type in ["Object", "Object_Field", "Variable", "Index"]:
            return True
        else:
            return False
    
    def process_assignment(self, assign_stmt, PFG: PointerFlowGraph, LBlock_id, RBlock_id):
        # 处理赋值语句
        self.log_manager.log_info(f'Process Assignment:', False, 3)
        # 处理赋值语句的左值(注意左值可能有多个,例如 String new_name = name1 = name = "test";)
        # 左值的类型:(1)对象,(2)对象属性,(3)变量,(4)数据操作(这里指对象属性列表某一元素,例如stu.classmate.score[0])
        if len(assign_stmt.LValues) >= 10: # 处理Joern解析array失败的情况
            return
        L_Nodes = list()
        for LValue in assign_stmt.LValues:
            pfg_node = self.process_stmt_data(LValue, LBlock_id, PFG, {"nodes": [], "field_edges": []}, add_node_flag = True)
            if pfg_node is None:
                continue
            elif pfg_node.node_type == "Temporary":
                continue
            else:
                L_Nodes.append({"pfg_node": pfg_node, "stmt": LValue})
        # 清理左值节点在PFG图中的数据流边(赋值语句相当于重新定义了此变量,所以需要将这个节点的一些边删除,注意:并没有将其所有边都删掉)
        for L_Node_dict in L_Nodes:
            L_Node = L_Node_dict["pfg_node"]
            PFG.clean_edge_to_target(L_Node)
            PFG.clean_edge_from_target(L_Node)
            PFG.clean_field_edge(L_Node)
        # 处理赋值语句的右值(右值只能有一个)
        # 右值的类型:(1)对象,(2)对象属性,(3)变量,(4)数据操作,(5)字面量,(6)类的函数调用,(7)普通函数调用
        R_Node = self.process_stmt_data(assign_stmt.RValue, RBlock_id, PFG, {"nodes": [], "field_edges": []}, add_node_flag = True)
        # 添加节点,创建数据流边和属性边
        if self.need_add(R_Node):
            PFG.add_node(node = R_Node, stmt = assign_stmt.RValue)
            self.log_manager.log_info(f'Right Node:', False, 3)
            self.log_manager.log_info(f'{R_Node.to_string()}', False, 4)
        num = -1
        for L_Node_dict in L_Nodes:
            num += 1
            L_Node = L_Node_dict["pfg_node"]
            if R_Node is None:
                continue
            elif R_Node.node_type == "PHPArray":
                if self.need_add(L_Node):
                    PFG.add_node(node = L_Node, stmt = L_Node_dict["stmt"])
                # 处理含有php array变量的赋值语句
                for item in R_Node.attributes:
                    if isinstance(item, dict) and "index" in item.keys() and "value" in item.keys() and "index_stmt" in item.keys() and "value_stmt" in item.keys():
                        if item["value"] is not None:
                            # 先将右值插入到PFG中
                            if self.need_add(item["value"]):
                                PFG.add_node(node = item["value"], stmt = item["value_stmt"])
                            # 构造PFG Node与操作数的Stmt
                            operated_pfg_node = copy.deepcopy(L_Node)
                            index_stmt = copy.deepcopy(item["index_stmt"])
                            operand_pfg_node = self.create_index_pfg_node(operated_pfg_node, index_stmt, PFG, LBlock_id)
                            operand_stmt = Operation()
                            operand_stmt.code = None
                            operand_stmt.cpg_id = None
                            operand_stmt.operator = NodeOperator.IndexAccess
                            operand_stmt.operands.append(copy.deepcopy(L_Node_dict["stmt"]))
                            operand_stmt.operands.append(copy.deepcopy(index_stmt))
                            operand_stmt.type = item["value_stmt"].type if hasattr(item["value_stmt"], "type") else None
                            operand_stmt.value = item["value_stmt"].value if hasattr(item["value_stmt"], "value") else None
                            try:
                                operand_json = PFG.stmt2json(copy.deepcopy(operand_stmt))
                                operand_stmt.code = PFG.json2str(operand_json)
                            except:
                                pass
                            # 赋值
                            operand_pfg_node.value = item["value"].value
                            operand_pfg_node.is_class = item["value"].is_class
                            operand_pfg_node.is_taint = item["value"].is_taint # 污点传播
                            operand_pfg_node.update_signature()
                            # 添加节点,创建属性边
                            if self.need_add(operand_pfg_node):
                                PFG.add_node(node = operand_pfg_node, stmt = operand_stmt, expression = item["value_stmt"])
                                if self.need_add(operated_pfg_node):
                                    PFG.add_field_edge(operated_pfg_node, operand_pfg_node)
                                # 更新节点的污点、签名等信息
                                self.update_value_taint(operand_pfg_node, PFG)
                                operand_pfg_node.update_signature()
                                PFG.add_node(node = operand_pfg_node, stmt = operand_stmt, expression = item["value_stmt"])
            else:
                # 处理不含php array变量的赋值语句
                if L_Node.node_type != "Index" and R_Node.own_type is not None:
                    if R_Node.own_type != "ANY":
                        L_Node.own_type = R_Node.own_type
                L_Node.value = R_Node.value
                L_Node.is_class = R_Node.is_class
                L_Node.is_taint = R_Node.is_taint # 污点传播
                L_Node.update_signature()
                self.log_manager.log_info(f'Left Node[{str(num)}]:', False, 3)
                self.log_manager.log_info(f'{L_Node.to_string()}', False, 4)
                if self.need_add(L_Node):
                    PFG.add_node(node = L_Node, stmt = L_Node_dict["stmt"], expression = assign_stmt.RValue)
                    PFG.propagate_taint(L_Node) # 污点传播
                    if self.need_add(R_Node):
                        PFG.add_data_flow_edge(R_Node, L_Node)

# ======================================== Assignment Process End ========================================

# ======================================== Call Process Start ========================================
    def extract_calls(self, stmt, call_stmts, log_level = 3):
        # 提取出一条语句中的所有函数调用
        num = -1
        self.log_manager.log_info(f'Extract All Call Stmt From: {str(stmt)}', False, log_level)
        if stmt is not None:
            if stmt.node_type == "Assignment":
                for LValue in stmt.LValues:
                    num += 1
                    self.log_manager.log_info(f'Processing Assignment Stmt LValues[{str(num)}]', False, log_level + 1)
                    self.extract_calls(LValue, call_stmts, log_level + 1)
                self.log_manager.log_info(f'Processing Assignment Stmt RValue[0]', False, log_level + 1)
                self.extract_calls(stmt.RValue, call_stmts, log_level + 1)
            elif stmt.node_type in ["ObjCall", "CommonCall"]:
                if stmt.code.lower().find("new ") == -1: # 不希望处理初始化函数
                    call_stmts.append(stmt)
                    for argument_index in stmt.arguments.keys():
                        argument = stmt.arguments[argument_index]
                        num += 1
                        self.log_manager.log_info(f'Processing Call Arguments[{str(num)}]', False, log_level + 1)
                        self.extract_calls(argument, call_stmts, log_level + 1)
            elif stmt.node_type == "Operation":
                if stmt.operator != NodeOperator.IndexAccess:
                    for operand in stmt.operands:
                        num += 1
                        self.log_manager.log_info(f'Processing Operation Operands[{str(num)}]', False, log_level + 1)
                        self.extract_calls(operand, call_stmts, log_level + 1)
            elif stmt.node_type in ["Object", "Object_Field", "Variable", "Literal"]:
                pass # 递归结束条件

    def process_call(self, stmt, PFG: PointerFlowGraph, code_block_id):
        # 处理所有函数调用语句(实参向形参转换过程本质上也是一个赋值过程: 形参 = 实参)
        for argument_index in stmt.arguments.keys():
            if argument_index in stmt.method.parameters.keys():
                assign_stmt = Assign()
                assign_stmt.LValues.append(stmt.method.parameters[argument_index]) # 形参
                assign_stmt.RValue = stmt.arguments[argument_index] # 实参
                self.process_assignment(
                    assign_stmt = assign_stmt,
                    PFG = PFG,
                    LBlock_id = stmt.cpg_id,
                    RBlock_id = code_block_id
                )

    def record_return_result(self, stmt: MethodReturn, PFG: PointerFlowGraph, code_block_id):
        # 记录函数返回值
        node_map = {"nodes": [], "field_edges": []}
        return_pfg_node = self.process_stmt_data(stmt, code_block_id, PFG, node_map, add_node_flag = True)
        if return_pfg_node is not None:
            PFG.call_return[code_block_id] = return_pfg_node

# ======================================== Call Process End ========================================

# ======================================== Taint Analysis Start ========================================
    def update_taint_config(self, call_stmt):
        # 更新taint config文件
        short_name = None
        if call_stmt is not None:
            if call_stmt.method is not None:
                if call_stmt.method.shortName is not None:
                    short_name = call_stmt.method.shortName
        if short_name is not None:
            if short_name not in self.taint_config["sources"].keys() and \
               short_name not in self.taint_config["sinks"].keys() and \
               short_name not in self.taint_config["transfers"].keys() and \
               short_name not in self.taint_config["sanitizer"].keys() and \
               short_name not in self.taint_config["harmless"] and \
               short_name not in self.taint_config["redirect"].keys() and \
               short_name not in self.taint_config["new"].keys():
                if call_stmt.code is not None:
                    if not call_stmt.code.startswith("$"):
                        self.taint_config["new"][short_name] = dict()
                        self.taint_config["new"][short_name]["from"] = None
                        self.taint_config["new"][short_name]["to"] = None
                        self.taint_config["new"][short_name]["type"] = call_stmt.method.methodReturn
                        self.taint_config["new"][short_name]["signature"] = call_stmt.method.signature
                        self.taint_config["new"][short_name]["cpg_id"] = call_stmt.cpg_id
                        self.taint_config["new"][short_name]["code"] = call_stmt.code
                        with open(self.taint_config_path, "w", encoding = "utf-8") as f:
                            json.dump(self.taint_config, f, ensure_ascii = False, indent = 4)

    def taint_analysiss(self, vuln_type: str, call_stmt, PFG: PointerFlowGraph, code_block_id):
        # TODO:增加污点数据是否到达了sink函数的判断,方便后续摘要处理
        # 对外部函数进行污点分析(注意:taint_config的下标从1开始)
        self.interest_flag = False
        flag = True # 是否需要记录该函数
        return_pfg_node = PFGNode(node_type = "Temporary")
        # 取出函数short_name
        short_name = None
        if call_stmt is not None:
            if call_stmt.method is not None:
                if call_stmt.method.shortName is not None:
                    short_name = call_stmt.method.shortName
        if short_name is not None:
            if short_name not in self.taint_config["harmless"]:
                # 处理污点传播函数
                if short_name in self.taint_config["transfers"].keys():
                    if self.taint_config["transfers"][short_name]["from"] == "base":
                        if self.taint_config["transfers"][short_name]["to"] == "result":
                            # base-to-result
                            if "0" in call_stmt.arguments:
                                base_pfg_node = self.process_stmt_data(call_stmt.arguments["0"], code_block_id, PFG, {"nodes": [], "field_edges": []}, add_node_flag = True)
                                return_pfg_node.is_taint = base_pfg_node.is_taint
                                return_pfg_node.own_type = self.taint_config["transfers"][short_name]["type"]
                                flag = False
                    elif self.taint_config["transfers"][short_name]["from"] >= 1:
                        taint_argument = None
                        taint_pfg_node = None
                        arg_num_index = self.taint_config["transfers"][short_name]["from"]
                        if arg_num_index <= len(list(call_stmt.arguments.keys())):
                            arg_str_index = list(call_stmt.arguments.keys())[arg_num_index - 1]
                            taint_argument = call_stmt.arguments[arg_str_index]
                            taint_pfg_node = self.process_stmt_data(taint_argument, code_block_id, PFG, {"nodes": [], "field_edges": []}, add_node_flag = True)
                        if self.taint_config["transfers"][short_name]["to"] == "result":
                            # arg-to-result
                            if taint_pfg_node is not None:
                                return_pfg_node.is_taint = taint_pfg_node.is_taint
                                return_pfg_node.own_type = self.taint_config["transfers"][short_name]["type"]
                                flag = False
                        elif self.taint_config["transfers"][short_name]["to"] == "base":
                            # arg-to-base
                            if taint_pfg_node is not None:
                                if taint_pfg_node.is_taint:
                                    if "0" in call_stmt.arguments:
                                        base_pfg_node = self.process_stmt_data(call_stmt.arguments["0"], code_block_id, PFG, {"nodes": [], "field_edges": []}, add_node_flag = True)
                                        PFG.make_taint(base_pfg_node)
                                        PFG.propagate_taint(base_pfg_node)
                                        flag = False
                # 处理漏洞触发点
                elif short_name in self.taint_config["sinks"].keys() and (vuln_type == self.taint_config["sinks"][short_name]["vuln_type"] or vuln_type == "all"):
                    flag = False
                    arg_num_index = self.taint_config["sinks"][short_name]["index"]
                    if arg_num_index <= len(list(call_stmt.arguments.keys())):
                        arg_str_index = list(call_stmt.arguments.keys())[arg_num_index - 1]
                        sink_argument = call_stmt.arguments[arg_str_index]
                        sink_pfg_node = self.process_stmt_data(sink_argument, code_block_id, PFG, {"nodes": [], "field_edges": []}, ignore_none = True, add_node_flag = True)
                        if sink_pfg_node.is_taint:
                            return_pfg_node.is_taint = True
                            self.interest_flag = True
                        else:
                            if sink_pfg_node.identifier:
                                tainted_parameter_list = PFG.get_tainted_parameters()
                                for tainted_parameter in tainted_parameter_list:
                                    if sink_pfg_node.identifier.find(tainted_parameter) != -1:
                                        return_pfg_node.is_taint = True
                                        self.interest_flag = True
                # 处理重定向函数
                elif short_name in self.taint_config["redirect"].keys():
                    flag = False
                    arg_num_index = self.taint_config["redirect"][short_name]
                    if arg_num_index <= len(list(call_stmt.arguments.keys())):
                        arg_str_index = list(call_stmt.arguments.keys())[arg_num_index - 1]
                        redirect_argument = call_stmt.arguments[arg_str_index]
                        if redirect_argument is not None:
                            redirect_pfg_node = self.process_stmt_data(redirect_argument, code_block_id, PFG, {"nodes": [], "field_edges": []}, ignore_none = True, add_node_flag = True)
                            if redirect_pfg_node is not None:
                                if redirect_pfg_node.value is not None:
                                    self.redirect_urls.append(redirect_pfg_node.value)
                # 处理清理函数
                elif short_name in self.taint_config["sanitizer"].keys():
                    flag = False
                    arg_num_index = self.taint_config["sanitizer"][short_name]
                    if arg_num_index < 1:
                        return_pfg_node.is_taint = False
                    else:
                        if arg_num_index <= len(list(call_stmt.arguments.keys())):
                            arg_str_index = list(call_stmt.arguments.keys())[arg_num_index - 1]
                            sink_argument = call_stmt.arguments[arg_str_index]
                            if sink_argument is not None:
                                return_pfg_node.is_taint = False # 清理污点
                # 处理未记录函数(这里采用了Over-Approximate的做法:只要参数之一被污染了,那么就认为该函数的返回值被污染了)
                else:
                    for arg_str_index in call_stmt.arguments.keys():
                        argument_stmt = call_stmt.arguments[arg_str_index]
                        if argument_stmt is not None:
                            argument_pfg_node = self.process_stmt_data(argument_stmt, code_block_id, PFG, {"nodes": [], "field_edges": []}, ignore_none = True, add_node_flag = True)
                            if argument_pfg_node is not None:
                                if argument_pfg_node.is_taint:
                                    return_pfg_node.is_taint = True
                                    break
            else:
                flag = False
        if flag:
            self.update_taint_config(call_stmt) # 记录函数信息
        # 运行内置函数,记录base、return的实际值与类型
        need_process = True
        arguments_map = dict()
        base_stmt = None
        base_pfg_node = None
        for arg_str_index in call_stmt.arguments.keys():
            argument_stmt = call_stmt.arguments[arg_str_index]
            if argument_stmt is not None:
                argument_pfg_node = self.process_stmt_data(argument_stmt, code_block_id, PFG, {"nodes": [], "field_edges": []}, add_node_flag = True)
                if argument_pfg_node is not None:
                    arguments_map[arg_str_index] = argument_pfg_node.value
                    if arg_str_index == "0":
                        base_stmt = copy.deepcopy(argument_stmt)
                        base_pfg_node = copy.deepcopy(argument_pfg_node)
        if base_pfg_node is not None:
            if base_pfg_node.value is None:
                need_process = False
            if base_pfg_node.identifier is not None and short_name is not None:
                need_process = True
                short_name = str(base_pfg_node.identifier) + "." + short_name
        filepath = self.code_manager.get_filepath(call_stmt)
        if filepath is None or short_name is None:
            need_process = False
        if need_process:
            try:
                # 注意:不能根据value来改变own_type
                error_flag, result = process_func(filepath, short_name, arguments_map)
                if not error_flag and isinstance(result, dict):
                    if "base" in result.keys():
                        if base_pfg_node.value is not None:
                            base_pfg_node.value = result["base"]
                            base_pfg_node.update_signature()
                            if self.need_add(base_pfg_node):
                                PFG.add_node(node = base_pfg_node, stmt = base_stmt)
                    if "result" in result.keys():
                        return_pfg_node.value = result["result"]
            except:
                pass
        PFG.call_return[call_stmt.cpg_id] = return_pfg_node
        
# ======================================== Taint Analysis End ========================================

    def analyze_stmt(self, stmt, PFG_in: PointerFlowGraph, code_block_id: any, have_summary = False):
        # 分析CPG节点,更新指针流图
        self.interest_flag = False
        PFG_out = copy.deepcopy(PFG_in)
        if stmt:
            if stmt.node_type == "Assignment":
                # 处理赋值语句
                self.process_assignment(
                    assign_stmt = stmt,
                    PFG = PFG_out,
                    LBlock_id = code_block_id,
                    RBlock_id = code_block_id
                )
            elif stmt.node_type in ["ObjCall", "CommonCall"] and not have_summary:
                self.process_call(stmt, PFG_out, code_block_id) # 未来的优化点:对于内置函数没有处理的意义
            elif stmt.node_type == "MethodReturn":
                self.record_return_result(stmt, PFG_out, code_block_id)
            elif stmt.node_type == "Operation":
                self.process_stmt_data(stmt, code_block_id, PFG_out, {"nodes": [], "field_edges": []}, add_node_flag = True)
        return PFG_out

    def init_taint_PFG(self, vuln_type, code_block_id, taint_cpg_node: dict, condition_node_dicts: list):
        # 初始化一个指针流图,并设置原始污点变量
        PFG = PointerFlowGraph()
        PFG.pfg_stmt_path = os.path.join(self.joern_server.pfg_stmt_root, str(code_block_id))
        PFG.call_return = dict()
        if taint_cpg_node is not None:
            taint_stmt = self.joern_server.parse_stmt(taint_cpg_node)
            Node_map = {"nodes": [], "field_edges": []}
            taint_pfg_node = self.process_stmt_data(
                stmt_data = taint_stmt,
                code_block_id = code_block_id,
                PFG = PFG,
                node_map = Node_map,
                add_node_flag = True
            )
            # 处理请求方式
            if taint_pfg_node.identifier is not None:
                if isinstance(taint_pfg_node.identifier, str) and taint_pfg_node.identifier.find("_GET") != -1 or taint_pfg_node.identifier.find("_POST") != -1:
                    request_method_node = self.joern_server.find_php_request_method_node()
                    if request_method_node:
                        request_method_stmt = self.joern_server.parse_stmt(request_method_node)
                        request_method_pfg_node = self.process_stmt_data(
                            stmt_data = request_method_stmt,
                            code_block_id = code_block_id,
                            PFG = PFG,
                            node_map = {"nodes": [], "field_edges": []},
                            add_node_flag = True
                        )
                        if taint_pfg_node.identifier.find("_GET") != -1:
                            request_method_pfg_node.value = "GET"
                        elif taint_pfg_node.identifier.find("_POST") != -1:
                            request_method_pfg_node.value = "POST"
                        if self.need_add(request_method_pfg_node):
                            PFG.add_node(node = request_method_pfg_node, stmt = request_method_stmt)
            if vuln_type in self.config_file["default_payload"].keys():
                taint_pfg_node.value = self.config_file["default_payload"][vuln_type]
            taint_pfg_node.is_taint = True
            if self.need_add(taint_pfg_node):
                PFG.add_node(node = taint_pfg_node, stmt = taint_stmt)
        # 记录条件分支中携带的信息
        for condition_node_dict in condition_node_dicts:
            if isinstance(condition_node_dict, dict):
                if "condition_node" in condition_node_dict.keys() and "operation_result" in condition_node_dict.keys():
                    conditon_dict = dict()
                    conditon_dict["condition_stmt"] = self.joern_server.parse_stmt(condition_node_dict["condition_node"])
                    conditon_dict["operation_result"] = condition_node_dict["operation_result"]
                    PFG = self.record_condition(conditon_dict, PFG, code_block_id)
                elif "condition_stmt" in condition_node_dict.keys() and "operation_result" in condition_node_dict.keys():
                    PFG = self.record_condition(condition_node_dict, PFG, code_block_id)
        return PFG
    
    def get_switch_case_stmts(self, condition_stmt, condition_cpg_node):
        # 获取Switch语句各个分支的条件(返回一个数据操作类)
        case_nodes = self.joern_server.find_switch_case(condition_cpg_node)
        case_stmts = list()
        for case_node in case_nodes:
            new_stmt = Operation()
            if "name" in case_node.keys() and "code" in case_node.keys():
                if case_node["name"] == "default" and case_node["code"] == "default":
                    new_stmt.operator = "default"
                    case_stmts.append(new_stmt)
                    continue
            case_stmt = self.joern_server.parse_stmt(case_node)
            new_stmt.operator = NodeOperator.EQUALS
            new_stmt.code = f"{condition_stmt.code} == {case_stmt.code}"
            new_stmt.operands.append(condition_stmt)
            new_stmt.operands.append(case_stmt)
            case_stmts.append(new_stmt)
        return case_stmts

    def need_delete_else_branch(self, condition_cpg_node: dict):
        # 判断是否要删除ELSE分支
        branch_cpg_nodes = self.joern_server.find_cfgOut(condition_cpg_node)
        if (branch_cpg_nodes is None) or (len(branch_cpg_nodes) < 2):
            return False
        else:
            else_cpg_node = branch_cpg_nodes[1]
            if isinstance(else_cpg_node, dict):
                cfgin_cpg_nodes = self.joern_server.find_cfgIn(else_cpg_node)
                if isinstance(cfgin_cpg_nodes, list):
                    if len(cfgin_cpg_nodes) == 1:
                        return True
        return False

    def extract_equal_stmts(self, stmt, code_block_id: str, PFG: PointerFlowGraph, equal_stmts: list, operation_result: bool):
        # 提取所有判断值是否相等的语句 TODO:对OR条件的处理可能存在问题
        if stmt.node_type == "Operation":
            if stmt.operator == NodeOperator.EQUALS:
                if operation_result:
                    pfg_node = self.process_stmt_data(stmt, code_block_id, PFG, {"nodes": [], "field_edges": []})
                    if pfg_node.value is None:
                        equal_stmts.append(stmt)
            elif stmt.operator == NodeOperator.NOT_EQUALS:
                if not operation_result:
                    pfg_node = self.process_stmt_data(stmt, code_block_id, PFG, {"nodes": [], "field_edges": []})
                    if pfg_node.value is None:
                        equal_stmts.append(stmt)
            elif stmt.operator in [NodeOperator.LOGIC_AND, NodeOperator.LOGIC_OR]:
                for operand_stmt in stmt.operands:
                    self.extract_equal_stmts(operand_stmt, code_block_id, PFG, equal_stmts, True)

    def record_condition(self, conditon_dict: dict, PFG_out: PointerFlowGraph, code_block_id):
        # 在PFG中记录所应满足的条件
        PFG = copy.deepcopy(PFG_out)
        if isinstance(conditon_dict, dict):
            if "condition_stmt" in conditon_dict.keys() and "operation_result" in conditon_dict.keys():
                condition_stmt = conditon_dict["condition_stmt"]
                if condition_stmt is not None:
                    equal_stmts = list()
                    self.extract_equal_stmts(condition_stmt, code_block_id, PFG_out, equal_stmts, conditon_dict["operation_result"])
                    for equal_stmt in equal_stmts:
                        if len(equal_stmt.operands) == 2:
                            # 处理变量和常量的位置
                            var_pos = None; literal_pos = None
                            for i in range(0, len(equal_stmt.operands)):
                                operand_stmt = equal_stmt.operands[i]
                                if operand_stmt is not None:
                                    operand_pfg_node = self.process_stmt_data(operand_stmt, code_block_id, PFG, {"nodes": [], "field_edges": []})
                                    if self.need_add(operand_pfg_node) and operand_pfg_node.value is None:
                                        var_pos = i
                                        break
                            if var_pos == 0:
                                literal_pos = 1
                            elif var_pos == 1:
                                literal_pos = 0
                            if var_pos is not None and literal_pos is not None:
                                # 将条件语句转换为赋值语句,随后处理这个赋值语句就可以记录其对应的值
                                assign_stmt = Assign()
                                assign_stmt.LValues.append(equal_stmt.operands[var_pos])
                                assign_stmt.RValue = equal_stmt.operands[literal_pos]
                                self.process_assignment(
                                    assign_stmt = assign_stmt,
                                    PFG = PFG,
                                    LBlock_id = code_block_id,
                                    RBlock_id = code_block_id
                                )
        return PFG

    def select_successors(self, stmt: ControlStructure, cpg_node: dict, all_successors: list, PFG: PointerFlowGraph, code_block_id):
        # 根据指针流图选择合适的分支,暂时只处理IF、SWITCH、WHILE、DO、FOR 5种语句 TODO:未来可优化
        successors = list()
        condition_dicts = list()
        total_condition_dicts = list()
        if stmt.controlStructureType in ["IF", "SWITCH", "WHILE", "DO", "FOR"]:
            condition_cpg_node = self.joern_server.find_control_condition(cpg_node)
            condition_stmt = self.joern_server.parse_stmt(condition_cpg_node)
            if condition_cpg_node:
                if stmt.controlStructureType in ["IF", "WHILE", "DO", "FOR"]:
                    # 获取for循环语句的初始化、条件和更新3个部分的CPG Nodes
                    for_cpg_nodes = list()
                    init_cpg_node = None
                    init_stmt = None
                    update_cpg_node = None
                    update_stmt = None
                    if stmt.controlStructureType == "FOR":
                        for_cpg_nodes = self.joern_server.find_for_parts(cpg_node)
                        if len(for_cpg_nodes) == 3:
                            init_cpg_node = for_cpg_nodes[0]
                            update_cpg_node = for_cpg_nodes[2]
                            init_stmt = self.joern_server.parse_stmt(init_cpg_node)
                            update_stmt = self.joern_server.parse_stmt(update_cpg_node)
                    # 处理for循环语句的初始化语句 TODO:不同语言的for循环中的变量是否是全局变量还需要研究(python和java对于for循环的处理就明显不同)
                    if init_stmt is not None:
                        PFG = self.analyze_stmt(init_stmt, PFG, code_block_id)
                    # 根据控制结构条件是否成立选择合适的后继节点
                    if len(all_successors) >= 1:
                        total_condition_dicts.append({"condition_stmt": condition_stmt, "operation_result": True})
                    if len(all_successors) >= 2:
                        total_condition_dicts.append({"condition_stmt": condition_stmt, "operation_result": False})
                    self.log_manager.log_info(f'Processing {stmt.controlStructureType} ControlStructure: [code: {stmt.code}]', False, 3)
                    node_map = {"nodes": [], "field_edges": []}
                    condition_pfg_node = self.process_stmt_data(condition_stmt, code_block_id, PFG, node_map, add_node_flag = True)
                    condition_result = self.calculate_operation(operands = [condition_pfg_node], operator = "no_operator")
                    if condition_result.value is not None:
                        # 在这里之所以能够直接根据all_successors的下标来确定True和False的分支,是因为all_successors是按照先True后False的顺序排列的(CPG的特性)
                        if condition_result.value:
                            if len(all_successors) >= 1:
                                successors.append(all_successors[0])
                                condition_dicts.append({"condition_stmt": condition_stmt, "operation_result": True})
                                self.log_manager.log_info(f'Select Successor node: [cpg id: {all_successors[0][NodeField.ID]}] [code: {all_successors[0]["code"]}]', False, 3)
                                self.conditions.append(condition_stmt.code)
                                # 找分支语句的后继节点(不是找条件语句的后继节点)
                                if len(all_successors) >= 2 and self.need_delete_else_branch(condition_cpg_node):
                                    self.code_manager.record_delete_line(all_successors[1])
                        else:
                            if len(all_successors) >= 2:
                                successors.append(all_successors[1])
                                condition_dicts.append({"condition_stmt": condition_stmt, "operation_result": False})
                                self.log_manager.log_info(f'Select Successor node: [cpg id: {all_successors[1][NodeField.ID]}] [code: {all_successors[1]["code"]}]', False, 3)
                                self.conditions.append(condition_stmt.code)
                                self.code_manager.record_delete_line(all_successors[0])  
                    # 处理for循环语句的更新语句
                    if update_stmt is not None:
                        PFG = self.analyze_stmt(init_stmt, PFG, code_block_id)
                elif stmt.controlStructureType == "SWITCH":
                    self.log_manager.log_info(f'Processing SWITCH ControlStructure: [code: {stmt.code}]', False, 3)
                    case_stmts = self.get_switch_case_stmts(condition_stmt, condition_cpg_node)
                    for i in range(len(case_stmts)):
                        case_stmt = case_stmts[i]
                        if i <= (len(all_successors) - 1):
                            total_condition_dicts.append({"condition_stmt": case_stmt, "operation_result": True})
                    keep_index = None
                    for i in range(len(case_stmts)):
                        case_stmt = case_stmts[i]
                        if i <= (len(all_successors) - 1):
                            if case_stmt.operator != "default":
                                node_map = {"nodes": [], "field_edges": []}
                                case_pfg_node = self.process_stmt_data(case_stmt, code_block_id, PFG, node_map, add_node_flag = True)
                                case_result = self.calculate_operation(operands = [case_pfg_node], operator = "no_operator")
                                if case_result.value is not None:
                                    if case_result.value:
                                        successors.append(all_successors[i])
                                        condition_dicts.append({"condition_stmt": case_stmt, "operation_result": True})
                                        self.conditions.append(case_stmt.code)
                                        self.log_manager.log_info(f'Select SWITCH Successor: [cpg id: {all_successors[i][NodeField.ID]}] [code: {all_successors[i]["code"]}]', False, 3)
                                        keep_index = i
                                        break
                                else:
                                    successors.append(all_successors[i])
                                    condition_dicts.append({"condition_stmt": case_stmt, "operation_result": True})
                            else:
                                # 当其它分支都没有被判定为进入过,就需要将default分支对应的节点加入到successors中
                                successors.append(all_successors[i])
                                condition_dicts.append({"condition_stmt": case_stmt, "operation_result": True})
                                self.log_manager.log_info(f'Select SWITCH Successor: [cpg id: {all_successors[i][NodeField.ID]}] [code: {all_successors[i]["code"]}]', False, 3)
                                keep_index = i
                                break
                    if keep_index is not None:
                        for j in range(0, len(all_successors)):
                            if j != keep_index:
                                self.code_manager.record_delete_line(all_successors[j])
        if successors == []:
            successors = all_successors
            condition_dicts = total_condition_dicts
        return successors, condition_dicts

    def collect_db_triples(self, db_operation: dict, cpg_node: dict, PFG: PointerFlowGraph, need_LLM = True):
        # 收集DB三元组相关信息 TODO:思考是否一定需要提到了污点变量名称才来检查?(对于那个Full Name参数注入的漏洞,似乎不需要啊)
        taint_parameters = list(set(PFG.get_tainted_parameters()))
        keywords = self.vuln_keywords["write"]
        keywords.extend(self.vuln_keywords["read"])
        flag = False
        vuln_parameter = None
        if cpg_node is not None and isinstance(cpg_node, dict):
            if "code" in cpg_node.keys():
                code = cpg_node["code"]
                if code:
                    for taint_parameter in taint_parameters:
                        if flag:
                            break
                        for keyword in keywords:
                            if code.find(taint_parameter) != -1 and code.lower().find(keyword) != -1:
                                flag = True
                                vuln_parameter = taint_parameter
                                break
        if flag:
            parent_node = self.joern_server.find_astParent_until_top(cpg_node)
            if parent_node is not None and isinstance(parent_node, dict):
                if NodeField.ID in parent_node.keys():
                    if parent_node[NodeField.ID] not in db_operation["cpg_ids"]:
                        db_operation["cpg_ids"].append(parent_node[NodeField.ID])
                        if need_LLM:
                            db_triple = self.model_manager.extract_db_triple(parent_node["code"], vuln_parameter)
                            if db_triple is not None:
                                if db_triple["answer"].lower().find("yes") != -1 and db_triple["answer"].lower().find("no") == -1:
                                    db_triple["code"] = parent_node["code"]
                                    db_operation["db_triples"].append(db_triple)
                                    if db_triple["operation"].lower().find("write") != -1 and db_triple["operation"].lower().find("read") == -1:
                                        db_operation["hava_write"] = True
                        else:
                            db_triple = {"answer":"?","table":"?","column":[],"vuln_column":"?","operation":"?","code": parent_node[NodeField.ID]}
                            db_operation["db_triples"].append(db_triple)
    
    def init_taint_analysis(self, code_block_id = None):
        # 初始化所有和污点分析相关的变量
        self.joern_server.log_level = 3
        self.log_manager.log_info(f'Start the Taint Analysis:', False, 2)
        self.interest_flag = False
        self.vuln_cpg_id_list = list()
        self.redirect_urls = list()
        self.conditions = list()
        self.worklist = list()
        if code_block_id is not None:
            pfg_stmt_path = os.path.join(self.joern_server.pfg_stmt_root, str(code_block_id))
        if not os.path.exists(pfg_stmt_path):
            os.makedirs(pfg_stmt_path, mode = 0o777)