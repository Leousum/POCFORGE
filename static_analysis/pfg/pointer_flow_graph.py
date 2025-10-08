import os
import copy
import json
from typing import List
import networkx as nx
import matplotlib.pyplot as plt
from static_analysis.pfg.node_status import NodeStatus
# import sys
# sys.path.append("/home/leousum/AutoPoC/")
from static_analysis.pfg.pfg_node import PFGNode


class PointerFlowGraph():
    def __init__(self):
        self.index = 0
        # self.nodes: List[PFGNode] = list() # 注意:不论是以self.nodes[i]还是node更改节点属性,其结果都会反馈到nodes数组和节点
        self.visited = list() # visited记录了已经访问了的节点,它代表vulnerable path
        self.pfg_stmt_path = None
        self.call_return = dict() # 函数返回值映射字典(key: Vulnerable Path,start id: stmt.cpg_id; value: PFG Temporary Node)
        self.graph = nx.DiGraph() # networkx图结构
        

    def get_visited_path(self):
        visited = list()
        for id in self.visited:
            visited.append(str(id))
        return "->".join(visited)
    
    def get_stmt_path(self, cpg_id):
        cpg_id = str(cpg_id)
        visited = list()
        for id in self.visited:
            visited.append(str(id))
        stmt_path = ""
        for i in range(len(visited)):
            visit = visited[i]
            stmt_path += visit
            if visit == cpg_id:
                break
            if i != (len(visited) - 1):
                stmt_path += "->"
        return stmt_path
    
    def json2str(self, data: dict):
        # 将Json格式的Stmt转换为字符串格式
        result = ""
        if data is not None:
            if isinstance(data, dict) and "node_type" in data.keys():
                if data["node_type"] in ["Object", "Variable"]:
                    result = str(data["identifier"])
                elif data["node_type"] == "Object_Field":
                    result = str(data["code"])
                elif data["node_type"] == "Literal":
                    result = str(data["value"])
                    if result.lower() == "true":
                        result = "True"
                    elif result.lower() == "false":
                        result = "False"
                elif data["node_type"] == "Operation":
                    if len(data["operands"]) == 1:
                        if data["operator"] == "<operator>.minus":
                            result = "-" + self.json2str(data["operands"][0])
                        elif data["operator"] == "<operator>.not":
                            result = "not" + self.json2str(data["operands"][0])
                        elif data["operator"] == "<operator>.logicalNot":
                            result = "not" + self.json2str(data["operands"][0])
                        elif data["operator"] == "<operator>.postIncrement":
                            result = self.json2str(data["operands"][0]) + "+1"
                        elif data["operator"] == "<operator>.postDecrement":
                            result = self.json2str(data["operands"][0]) + "-1"
                        elif data["operator"] == "<operator>.preIncrement":
                            result = self.json2str(data["operands"][0]) + "+ 1"
                        elif data["operator"] == "<operator>.preDecrement":
                            result = self.json2str(data["operands"][0]) + "-1"
                        elif data["operator"] == "no_operator":
                            result = (self.json2str(data["operands"][0]) + "!== NULL") + "or " + self.json2str(data["operands"][0])
                    elif len(data["operands"]) == 2:
                        if data["operator"] in ["<operator>.addition", "<operator>.assignmentPlus", "<operator>.concat", "<operator>.assignmentConcat", "<operator>.plus"]:
                            if (not self.json2str(data["operands"][0]).isdigit()) and (not self.json2str(data["operands"][1]).isdigit()):
                                result = self.json2str(data["operands"][0]) + self.json2str(data["operands"][1])
                            else:
                                result = self.json2str(data["operands"][0]) + "+" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.assignmentMinus":
                            result = self.json2str(data["operands"][0]) + "-" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.assignmentMultiplication":
                            result = self.json2str(data["operands"][0]) + "*" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.assignmentDivision":
                            result = self.json2str(data["operands"][0]) + "/" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operators>.assignmentModulo":
                            result = self.json2str(data["operands"][0]) + "%" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.subtraction":
                            result = self.json2str(data["operands"][0]) + "-" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.multiplication":
                            result = self.json2str(data["operands"][0]) + "*" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.division":
                            result = self.json2str(data["operands"][0]) + "/" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.floorDiv":
                            result = self.json2str(data["operands"][0]) + "//" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.modulo":
                            result = self.json2str(data["operands"][0]) + "%" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.exponentiation":
                            result = self.json2str(data["operands"][0]) + "**" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.and":
                            result = self.json2str(data["operands"][0]) + "&" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.or":
                            result = self.json2str(data["operands"][0]) + "|" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.xor":
                            result = self.json2str(data["operands"][0]) + "^" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.logicalAnd":
                            result = self.json2str(data["operands"][0]) + "and" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.logicalOr":
                            result = self.json2str(data["operands"][0]) + "or" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.equals":
                            result = self.json2str(data["operands"][0]) + "==" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.notEquals":
                            result = self.json2str(data["operands"][0]) + "!=" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.lessThan":
                            result = self.json2str(data["operands"][0]) + "<" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.greaterThan":
                            result = self.json2str(data["operands"][0]) + ">" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.lessEqualsThan":
                            result = self.json2str(data["operands"][0]) + "<=" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.greaterEqualsThan":
                            result = self.json2str(data["operands"][0]) + ">=" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.shiftLeft":
                            result = self.json2str(data["operands"][0]) + "<<" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.arithmeticShiftRight":
                            result = self.json2str(data["operands"][0]) + ">>" + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.coalesce":
                            result = "(" + self.json2str(data["operands"][0]) + "is not NULL) ? " + self.json2str(data["operands"][0]) + " : " + self.json2str(data["operands"][1])
                        elif data["operator"] == "<operator>.cast":
                            if data["operands"][0]["node_type"] == "Temporary":
                                result = f'{data["operands"][0]["type"]}({self.json2str(data["operands"][1])})'
                            elif data["operands"][1]["node_type"] == "Temporary":
                                result = f'{data["operands"][1]["type"]}({self.json2str(data["operands"][0])})'
                        elif data["operator"] == "<operator>.indexAccess":
                            flag = False
                            operated = self.json2str(data["operands"][0])
                            php_global_vars = ["_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_FILES", "_SESSION", "_ENV", "$GLOBALS"]
                            for var in php_global_vars:
                                if str(operated).find(var) != -1:
                                    flag = True
                                    break
                            if flag:
                                result = self.json2str(data["operands"][0]) + "['" + self.json2str(data["operands"][1]) + "']"
                            else:
                                result = self.json2str(data["operands"][0]) + "." + self.json2str(data["operands"][1])
                    elif len(data["operands"]) == 3:
                        if data["operator"] == "<operator>.conditional":
                            result = self.json2str(data["operands"][0]) + " ? " + self.json2str(data["operands"][1]) + " : " + self.json2str(data["operands"][2])
                elif data["node_type"] in ["ObjCall", "CommonCall"]:
                    result = str(data["code"])[:str(data["code"]).find("(") + 1]
                    if str(data["code"]).find("(") == -1 and str(data["code"]).find(" ") != -1:
                        result = str(data["code"])[:str(data["code"]).find(" ")]
                        result += "("
                    for argument_index in data["arguments"].keys():
                        result += self.json2str(data["arguments"][argument_index])
                        result += ","
                    result = result.strip(",")
                    result += ")"
                elif data["node_type"] == "Assignment":
                    for LValue in data["LValues"]:
                        result = result + self.json2str(LValue) + "="
                    result += self.json2str(data["RValue"])
                    result = result.strip("=")
                elif data["node_type"] == "MethodReturn":
                    result = "return " + self.json2str(data["return_result"])
                elif data["node_type"] == "PHPArray":
                    type = "dict"
                    result = ""
                    for item in data["array_items"]:
                        if isinstance(item, dict) and "index" in item.keys() and "value" in item.keys():
                            index = self.json2str(item["index"])
                            value = self.json2str(item["value"])
                            if index is not None and value is not None and index != "" and value != "":
                                if index.isdigit():
                                    type = "list"
                                    if value.isdigit():
                                        result = result + value + ", "
                                    else:
                                        result = result + "\"" + value + "\", "
                                else:
                                    if value.isdigit():
                                        result = result + "\"" + index + "\": " + value + ", "
                                    else:
                                        result = result + "\"" + index + "\": \"" + value + "\", "
                    if type == "list":
                        result = "[" + result.strip(", ") + "]"
                    else:
                        result = "{" + result.strip(", ") + "}"
                    if isinstance(data["oneself"], dict):
                        result = self.json2str(data["oneself"]) + "=" + result
        return result
        
    def traver_folder(self, data: dict):
        # 遍历PFG Node-Stmt映射文件夹,找到data的实际表达式
        expression = None
        if data is not None and os.path.exists(self.pfg_stmt_path):
            for filename in os.listdir(self.pfg_stmt_path):
                map_path = os.path.join(self.pfg_stmt_path, filename)
                if os.path.isfile(map_path) and filename.endswith('.json'):
                    try:
                        map_data = dict()
                        with open(map_path, "r", encoding = "utf-8") as f:
                            map_data = json.load(f)
                        if isinstance(map_data, dict):
                            if "stmt" in map_data.keys() and "expression" in map_data.keys():
                                if data == map_data["stmt"]:
                                    expression = map_data["expression"]
                                    break
                    except:
                        pass
        return expression

    def update_expression(self, origin: dict):
        # 更新表达式(此处可以不必为"Object"更新表达式)
        data = copy.deepcopy(origin)
        if data is not None:
            if isinstance(data, dict) and "node_type" in data.keys():
                if data["node_type"] == "Assignment":
                    for i in range(0, len(data["LValues"])):
                        data["LValues"][i] = self.update_expression(data["LValues"][i])
                    data["RValue"] = self.update_expression(data["RValue"])
                if data["node_type"] == "Variable":
                    data = self.traver_folder(data)
                elif data["node_type"] == "Object_Field":
                    data = self.traver_folder(data)
                elif data["node_type"] == "Operation":
                    for i in range(len(data["operands"])):
                        data["operands"][i] = self.update_expression(data["operands"][i])
                elif data["node_type"] in ["ObjCall", "CommonCall"]:
                    expression = self.traver_folder(data) # 寻找函数返回
                    if expression is not None:
                        data = expression
                    else:
                        for argument_index in data["arguments"].keys():
                            data["arguments"][argument_index] = self.update_expression(data["arguments"][argument_index])
                elif data["node_type"] in ["ObjMethod", "CommonMethod"]:
                    for parameter_index in data["parameters"].keys():
                        data["parameters"][parameter_index] = self.update_expression(data["parameters"][parameter_index])
                elif data["node_type"] == "MethodReturn":
                    data["return_result"] = self.update_expression(data["return_result"])
        return data

    def stmt2json(self, stmt, need_expression = False):
        # 将Stmt转换为Json格式,need_expression代表是否需要真实表达式
        data = dict()
        if stmt is not None:
            data = stmt.to_json()
            if need_expression:
                data = self.update_expression(data)
        return data

    def add_node(self, node: PFGNode, stmt = None, expression = None):
        # 添加节点
        node.pfg_id = self.index
        # if node.signature not in self.signature2id.keys():
        if node.signature not in set(self.graph.nodes):
            # self.signature2id[node.signature] = node.pfg_id
            # 设置新的全局变量为污点数据
            if node.identifier is not None:
                whole_identifier = self.get_whole_identifier(node, "")
                php_global_vars = ["_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_FILES", "_SESSION", "_ENV", "$GLOBALS"]
                for var in php_global_vars:
                    if whole_identifier.find(var) != -1:
                        # node.is_taint = True
                        node.status.remove(NodeStatus.UNTAINTED)
                        node.status.add(NodeStatus.TAINTED)
            # self.nodes.append(node)
            self.graph.add_node(node.signature, pfg_node=node) # graph中加入节点，signature作为唯一标识符,pfg_node作为节点属性
            self.index += 1
        else:
            # node.pfg_id = self.signature2id[node.signature]
            node.pfg_id = self.graph.nodes[node.signature]["pfg_node"].pfg_id
            # if node.pfg_id >= 0 and node.pfg_id <= (len(self.nodes) - 1):
                # self.nodes[node.pfg_id].value = node.value
                # self.nodes[node.pfg_id].is_class = node.is_class
                # self.nodes[node.pfg_id].is_taint = node.is_taint

            self.graph.nodes[node.signature]["pfg_node"].value = node.value
            self.graph.nodes[node.signature]["pfg_node"].is_class = node.is_class
            self.graph.nodes[node.signature]["pfg_node"].status = node.status
                
        # 记录PFG Node到Stmt的映射关系
        need_kepp = False
        if self.pfg_stmt_path is not None:
            if not os.path.exists(self.pfg_stmt_path):
                os.makedirs(self.pfg_stmt_path, mode = 0o777)
            map_path = os.path.join(self.pfg_stmt_path, str(node.pfg_id) + ".json")
            map_data = dict()
            if os.path.exists(map_path):
                try:
                    with open(map_path, "r", encoding = "utf-8") as f:
                        map_data = json.load(f)
                except:
                    map_data = dict()
            map_data["pfg_id"] = node.pfg_id
            # 记录PFG Node的实际表达式(里)
            if expression is not None:
                map_data["expression"] = expression.to_json()
                map_data["expression"] = self.update_expression(map_data["expression"]) # 更新表达式
                map_data["expression_str"] = self.json2str(map_data["expression"])
            # 记录PFG Node的原生Stmt(表)
            if stmt is not None:
                # if "stmt" not in map_data.keys():
                map_data["stmt"] = stmt.to_json()
                map_data["stmt_str"] = self.json2str(map_data["stmt"])
                if "expression" not in map_data.keys():
                    map_data["expression"] = stmt.to_json()
                    map_data["expression_str"] = self.json2str(map_data["expression"])
                # 对象的相互赋值没有必要建立映射(PFG中存在双向数据流来表示此关系)
                if map_data["stmt"] is not None and map_data["expression"] is not None:
                    need_kepp = True
                    if map_data["stmt"]["node_type"] == "Object" and map_data["expression"]["node_type"] == "Object":
                        map_data["expression"] = stmt.to_json()
                        map_data["expression_str"] = self.json2str(map_data["expression"])
            # 传播实际表达式(第一个条件代表赋值语句)
            if expression is not None and "expression" in map_data.keys():
                # if node.pfg_id >= 0 and node.pfg_id <= (len(self.nodes) - 1) and map_data["expression"] is not None:
                if map_data["expression"] is not None:
                    for other_node in self.find_nodes_by_short_signature(self.graph.nodes[node.signature]["pfg_node"]):
                        if self.is_actual_same(self.graph.nodes[node.signature]["pfg_node"], other_node):
                            other_map_data = dict()
                            other_map_path = os.path.join(self.pfg_stmt_path, str(other_node.pfg_id) + ".json")
                            if os.path.exists(other_map_path):
                                try:
                                    with open(other_map_path, "r", encoding = "utf-8") as f:
                                        other_map_data = json.load(f)
                                    if "stmt" in other_map_data.keys() and other_map_data["stmt"]["node_type"] != "Object":
                                        other_map_data["expression"] = copy.deepcopy(map_data["expression"])
                                        other_map_data["expression_str"] = self.json2str(other_map_data["expression"])
                                        with open(other_map_path, "w", encoding = "utf-8") as f:
                                            json.dump(other_map_data, f, ensure_ascii = False, indent = 4)
                                except:
                                    other_map_data = dict()
                                
            # 保存结果
            if need_kepp:
                with open(map_path, "w", encoding = "utf-8") as f:
                    json.dump(map_data, f, ensure_ascii = False, indent = 4)

    def get_data_flow_constraints(self):
        # 获取数据流控制依赖
        constraints = list()
        if os.path.exists(self.pfg_stmt_path):
            for filename in os.listdir(self.pfg_stmt_path):
                map_path = os.path.join(self.pfg_stmt_path, filename)
                if os.path.isfile(map_path) and filename.endswith('.json'):
                    try:
                        map_data = dict()
                        with open(map_path, "r", encoding = "utf-8") as f:
                            map_data = json.load(f)
                        if isinstance(map_data, dict):
                            if "stmt" in map_data.keys() and "expression" in map_data.keys():
                                if map_data["stmt"] != map_data["expression"] and map_data["stmt"] is not None and map_data["expression"] is not None:
                                    if map_data["stmt"]["node_type"] not in ["Temporary", "ObjCall", "CommonCall"]:
                                        constraint = dict()
                                        constraint["node_type"] = "Assignment"
                                        constraint["cpg_id"] = None
                                        constraint["code"] = str()
                                        constraint["LValues"] = list()
                                        constraint["LValues"].append(map_data["stmt"])
                                        constraint["RValue"] = map_data["expression"]
                                        constraint["code"] = self.json2str(constraint)
                                        constraints.append(constraint)
                    except:
                        pass
        return constraints

    def clean_field_edge(self, target_node: PFGNode):
        # 清理目标节点的所有属性边
        # if target_node.signature in self.signature2id.keys():
        #     node_id = self.signature2id[target_node.signature]
        #     if node_id >= 0 and node_id <= (len(self.nodes) - 1):
        #         self.nodes[node_id].fields.clear()
        if target_node.signature in set(self.graph.nodes):
            target_signature = target_node.signature
            edges_to_remove = []
            
            # 检查所有出边,找到所有属性边
            for successor in list(self.graph.successors(target_signature)):
                edge_data = self.graph.get_edge_data(target_signature, successor)
                if edge_data and edge_data.get('relationship') == 'field':
                    edges_to_remove.append((target_signature, successor))
            # 移除所有属性边
            for edge in edges_to_remove:
                self.graph.remove_edge(edge[0], edge[1])

    def clean_edge_from_target(self, target_node: PFGNode):
        # 清理所有目标节点指向其它节点的边
        # if target_node.signature in self.signature2id.keys():
        #     node_id = self.signature2id[target_node.signature]
        #     if node_id >= 0 and node_id <= (len(self.nodes) - 1):
        #         self.nodes[node_id].points2sets.clear()
        if target_node.signature in set(self.graph.nodes):
            target_signature = target_node.signature
            edges_to_remove = []
            
            # 检查所有出边,找到所有数据流边
            for successor in list(self.graph.successors(target_signature)):
                edge_data = self.graph.get_edge_data(target_signature, successor)
                if edge_data and edge_data.get('relationship') == 'dataflow':
                    edges_to_remove.append((target_signature, successor))
            # 移除所有数据流边
            for edge in edges_to_remove:
                self.graph.remove_edge(edge[0], edge[1])

    def clean_edge_to_target(self, target_node: PFGNode):
        # 清理所有指向目标节点的边
        # if target_node.signature in self.signature2id.keys():
        #     node_id = self.signature2id[target_node.signature]
        #     for i in range(len(self.nodes)):
        #         if node_id in self.nodes[i].points2sets:
        #             self.nodes[i].points2sets.remove(node_id)
        if target_node.signature in set(self.graph.nodes):
            target_signature = target_node.signature
            edges_to_remove = []
            
            # 检查所有入边,找到所有数据流边
            for predecessor in list(self.graph.predecessors(target_signature)):
                edge_data = self.graph.get_edge_data(predecessor, target_signature)
                if edge_data and edge_data.get('relationship') == 'dataflow':
                    edges_to_remove.append((predecessor, target_signature))
            # 移除所有数据流边
            for edge in edges_to_remove:
                self.graph.remove_edge(edge[0], edge[1])
    
    def add_field_edge(self, start_node: PFGNode, end_node: PFGNode):
        # 添加属性边
        
        # self.nodes[start_id].add_field(self.nodes[end_id])
        self.graph.add_edge(start_node.signature, end_node.signature, relationship="field")
        end_node.parent_signature = start_node.signature 

    def add_data_flow_edge(self, start_node: PFGNode, end_node: PFGNode):
        # 添加数据流边
        # start_id = start_node.pfg_id
        # end_id = end_node.pfg_id
        # self.nodes[start_id].add_data_flow(self.nodes[end_id])
        self.graph.add_edge(start_node.signature, end_node.signature, relationship="dataflow")
        if start_node.is_class:
            # self.nodes[end_id].add_data_flow(self.nodes[start_id])
            self.graph.add_edge(end_node.signature, start_node.signature, relationship="dataflow")
            # 检查开始节点是否还有其它关联的类
            # for id in self.nodes[start_id].points2sets:
            #     if id != end_id:
            #         if start_id in self.nodes[id].points2sets and self.nodes[id].is_class:
            #             self.nodes[id].is_taint = self.nodes[start_id].is_taint
            #             self.nodes[id].add_data_flow(self.nodes[end_id])
            #             self.nodes[end_id].add_data_flow(self.nodes[id])
            
            for out_node_signature in list(self.graph.successors(start_node.signature)):
                if self.graph.get_edge_data(start_node.signature, out_node_signature).get('relationship') == 'dataflow':
                    if out_node_signature != end_node.signature:
                        if start_node.signature in self.graph.predecessors(out_node_signature) and self.graph.get_edge_data(start_node.signature, out_node_signature).get('relationship') == 'dataflow' and self.graph.nodes[out_node_signature]["pfg_node"].is_class:
                            self.graph.nodes[out_node_signature]["pfg_node"].status = start_node.status
                            self.graph.add_edge(out_node_signature, end_node.signature, relationship="dataflow")
                            self.graph.add_edge(end_node.signature, out_node_signature, relationship="dataflow")
        # 传播污点
        # self.nodes[end_id].is_taint = self.nodes[start_id].is_taint
        self.graph.nodes[end_node.signature]["pfg_node"].status = self.graph.nodes[start_node.signature]["pfg_node"].status

    def get_fields_sig(self,target_node: PFGNode):
        # 获得节点的所有属性节点的签名,相当于之前定义的fields
        target_signature = target_node
        fields_sig = []
        for successor in list(self.graph.successors(target_signature)):
            edge_data = self.graph.get_edge_data(target_signature, successor)
            if edge_data and edge_data.get('relationship') == 'field':
                fields_sig.append(successor)
        return fields_sig

    def get_points2_sig(self,target_node: PFGNode):
        # 获得节点的所有数据流向节点的签名,相当于之前定义的points2sets
        target_signature = target_node
        points2_sig = []
        for successor in list(self.graph.successors(target_signature)):
            edge_data = self.graph.get_edge_data(target_signature, successor)
            if edge_data and edge_data.get('relationship') == 'dataflow':
                points2_sig.append(successor)
        return points2_sig

    def get_whole_identifier(self, node: PFGNode, whole_identifier: str):
        # 获取完整的标识符
        if node.node_type in ["Object", "Variable"]:
            whole_identifier = node.identifier + whole_identifier
        elif node.node_type in ["Object_Field", "Index"]:
            if node.node_type == "Object_Field":
                if node.identifier is not None:
                    whole_identifier = "." + node.identifier + whole_identifier
            else:
                if isinstance(node.identifier, str):
                    whole_identifier = f'[\\\"{node.identifier}\\\"]' + whole_identifier
                else:
                    whole_identifier = f'[{str(node.identifier)}]' + whole_identifier
            # if node.parent_pfg_id is not None:
            #     if node.parent_pfg_id >= 0 and node.parent_pfg_id <= (len(self.nodes) - 1):
            #         parent_node = self.nodes[node.parent_pfg_id]
            if node.parent_signature is not None:
                if node.parent_signature in set(self.graph.nodes):
                    parent_node = self.graph.nodes[node.parent_signature]["pfg_node"]
                    whole_identifier = self.get_whole_identifier(parent_node, whole_identifier)
        return whole_identifier

    def get_tainted_parameters(self):
        # 获取所有被污染变量标识符
        temp_vars = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"]
        php_global_vars = ["_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_FILES", "_SESSION", "_ENV", "$GLOBALS"]
        global_vars = ["$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE", "$_FILES", "$_SESSION", "$_ENV", "$GLOBALS"]
        identifiers = list()
        # for node in self.nodes:
        for node in list(nx.get_node_attributes(self.graph, 'pfg_node').values()):
            # if node.is_taint and node.identifier not in temp_vars:
            if NodeStatus.TAINTED in node.status and node.identifier not in temp_vars:
                identifiers.append(self.get_whole_identifier(node, ""))
        identifiers = list(set(identifiers))
        flag = False
        for i in range(0, len(identifiers)):
            if flag:
                break
            identifier = identifiers[i]
            for global_var in php_global_vars:
                if identifier.find(global_var) != -1:
                    flag = True
                    break
        if flag:
            for i in range(0, len(identifiers)):
                if not identifiers[i].startswith("$"):
                    identifiers[i] = "$" + identifiers[i]
        identifiers = list(set(identifiers) - set(temp_vars) - set(php_global_vars) - set(global_vars))
        return identifiers
    
    def make_taint(self, target_node: PFGNode):
        # 设置污点
        # if target_node.signature in self.signature2id.keys():
        #     node_id = self.signature2id[target_node.signature]
        #     if node_id >= 0 and node_id <= (len(self.nodes) - 1):
        #         self.nodes[node_id].own_type = target_node.own_type
        #         self.nodes[node_id].value = target_node.value
        #         self.nodes[node_id].is_class = target_node.is_class
        #         # self.nodes[node_id].is_taint = True
        #         self.nodes[node_id].status.add(NodeStatus.TAINTED)
        #         self.nodes[node_id].update_signature()
        target_signature = target_node.signature
        if target_signature in set(self.graph.nodes):
            self.graph.nodes[target_signature]["pfg_node"].value
            self.graph.nodes[target_signature]["pfg_node"].own_type = target_node.own_type
            self.graph.nodes[target_signature]["pfg_node"].value = target_node.value
            self.graph.nodes[target_signature]["pfg_node"].is_class = target_node.is_class
            # self.nodes[node_id].is_taint = True
            self.graph.nodes[target_signature]["pfg_node"].status.add(NodeStatus.TAINTED)
            self.graph.nodes[target_signature]["pfg_node"].update_signature()
    
    def propagate_taint(self, target_node: PFGNode):
        # 传播污点(由于base可能被污染,所以需要传播污点)
        
        # if target_node.signature in self.signature2id.keys():
        #     node_id = self.signature2id[target_node.signature]
        #     if node_id >= 0 and node_id <= (len(self.nodes) - 1):
        #         # 向上回溯迭代污点传播
        #         for node in self.find_nodes_by_short_signature(self.nodes[node_id]):
        #             if self.is_actual_same(self.nodes[node_id], node):
        #                 self.nodes[node.pfg_id].own_type = self.nodes[node_id].own_type
        #                 self.nodes[node.pfg_id].value = self.nodes[node_id].value
        #                 self.nodes[node.pfg_id].is_class = self.nodes[node_id].is_class
        #                 # self.nodes[node.pfg_id].is_taint = self.nodes[node_id].is_taint
        #                 self.nodes[node.pfg_id].status = self.nodes[node_id].status
        #                 self.nodes[node.pfg_id].update_signature()
        target_signature = target_node.signature
        if target_signature in set(self.graph.nodes):
        # 向上回溯迭代污点传播
            for node in self.find_nodes_by_short_signature(self.graph.nodes[target_signature]["pfg_node"]):
                if self.is_actual_same(self.graph.nodes[target_signature]["pfg_node"], node):
                    self.graph.nodes[node.signature]["pfg_node"].own_type = self.graph.nodes[target_signature]["pfg_node"].own_type
                    self.graph.nodes[node.signature]["pfg_node"].value = self.graph.nodes[target_signature]["pfg_node"].value
                    self.graph.nodes[node.signature]["pfg_node"].is_class = self.graph.nodes[target_signature]["pfg_node"].is_class
                    # self.nodes[node.pfg_id].is_taint = self.nodes[node_id].is_taint
                    self.graph.nodes[node.signature]["pfg_node"].status = self.graph.nodes[target_signature]["pfg_node"].status
                    self.graph.nodes[node.signature]["pfg_node"].update_signature()

    def find_nodes_by_short_signature(self, pfg_node: PFGNode):
        # 从PFG中查找所有具有相同短签名的节点(自身除外)
        nodes = list()
        # for node in self.nodes:
        #     if node.pfg_id != pfg_node.pfg_id:
        #         if node.short_signature == pfg_node.short_signature:
        #             nodes.append(node)
        for node_sig in set(self.graph.nodes):
            node = self.graph.nodes[node_sig]["pfg_node"]
            if node.pfg_id != pfg_node.pfg_id:
                if node.short_signature == pfg_node.short_signature:
                    nodes.append(node)
        return nodes

    def is_actual_same(self, node1: PFGNode, node2: PFGNode):
        # 判断两个PFGNode实际上是不是同一个节点
        if node1.pfg_id == node2.pfg_id:
            return True
        else:
            if node1.own_type == node2.own_type:
                if node1.is_class and node2.is_class:
                    # if node1.pfg_id in node2.points2sets and node2.pfg_id in node1.points2sets:
                    if node1.signature in self.get_points2_sig(node2) and node2.signature in self.get_points2_sig(node1):
                        return True
            else:
                return False
            # if node1.parent_pfg_id is not None and node2.parent_pfg_id is not None:
            #     parent_node1 = self.nodes[int(node1.parent_pfg_id)]
            #     parent_node2 = self.nodes[int(node2.parent_pfg_id)]
            if node1.parent_signature is not None and node2.parent_signature is not None:
                parent_node1 = self.graph.nodes[node1.parent_signature]["pfg_node"]
                parent_node2 = self.graph.nodes[node2.parent_signature]["pfg_node"]
                return self.is_actual_same(parent_node1, parent_node2)
        return False
    
    def get_structure(self, input_node: PFGNode, structure: dict):
        # 递归获取完整结构
        node_fields_sig = self.get_fields_sig(input_node)
        # if input_node.fields:
        if node_fields_sig:
            dict_flag = False
            list_flag = False
            # for field_pfg_id in input_node.fields:
            #     field_pfg_node = self.nodes[field_pfg_id]
            for node_field_sig in node_fields_sig:
                field_pfg_node = self.graph.nodes[node_field_sig]["pfg_node"]
                if isinstance(field_pfg_node.identifier, str):
                    dict_flag = True
                    break
                elif isinstance(field_pfg_node.identifier, int):
                    list_flag = True
                    break
            if dict_flag:
                if str(input_node.identifier) not in structure.keys():
                    structure[str(input_node.identifier)] = dict()
                # for field_pfg_id in input_node.fields:
                #     field_pfg_node = self.nodes[field_pfg_id]
                for node_field_sig in node_fields_sig:
                    field_pfg_node = self.graph.nodes[node_field_sig]["pfg_node"]
                    self.get_structure(field_pfg_node, structure[str(input_node.identifier)])
            elif list_flag:
                if str(input_node.identifier) not in structure.keys():
                    structure[str(input_node.identifier)] = list()
                # for field_pfg_id in input_node.fields:
                #     field_pfg_node = self.nodes[field_pfg_id]
                for node_field_sig in node_fields_sig:
                    field_pfg_node = self.graph.nodes[node_field_sig]["pfg_node"]
                    try:
                        index = int(field_pfg_node.identifier)
                        if index >= len(structure[str(input_node.identifier)]):
                            for _ in range(len(structure[str(input_node.identifier)]), index + 1):
                                structure[str(input_node.identifier)].append(None)
                        structure[str(input_node.identifier)][index] = field_pfg_node.value
                    except:
                        pass
        else:
            structure[str(input_node.identifier)] = input_node.value
            if input_node.value is None:
                # if input_node.points2sets:
                #     for id in input_node.points2sets:
                #         node = self.nodes[id]
                #         if node.value is not None:
                #             structure[str(input_node.identifier)] = node.value
                #             break
                node_points2_sig = self.get_points2_sig(input_node)
                if node_points2_sig:
                    for node_point2_sig in node_points2_sig:
                        node = self.graph.nodes[node_point2_sig]["pfg_node"]
                        if node.value is not None:
                            structure[str(input_node.identifier)] = node.value
                            break

    def get_user_input_structure(self):
        # 获取用户输入结构
        user_input = dict()
        # (1) 遍历节点列表,找到所有用户输入节点(TODO: 后面可能要加一个属性:is_user_input,用来记录是否来自用户输入)
        input_nodes = list()
        php_global_vars = ["_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_FILES"] # "_SESSION", "_ENV"
        # for node in self.nodes:
        for node_sig in set(self.graph.nodes):
            node = self.graph.nodes[node_sig]["pfg_node"]
            if node.identifier:
                for global_var in php_global_vars:
                    if str(node.identifier).find(global_var) != -1:
                        input_nodes.append(node)
        # (2) 依次处理用户输入节点
        for input_node in input_nodes:
            input_node_fields_sig = self.get_fields_sig(input_node)
            if input_node.identifier.find("_GET") != -1 or input_node.identifier.find("_POST") != -1 or input_node.identifier.find("_REQUEST") != -1:
                if "data" not in user_input.keys():
                    user_input["data"] = dict()
                # for id in input_node.fields:
                #     node = self.nodes[id]
                for node_field_sig in input_node_fields_sig:
                    node = self.graph.nodes[node_field_sig]["pfg_node"]
                    self.get_structure(node, user_input["data"])
            elif input_node.identifier.find("_SERVER") != -1:
                if "header" not in user_input.keys():
                    user_input["header"] = dict()
                for node_field_sig in input_node_fields_sig:
                    node = self.graph.nodes[node_field_sig]["pfg_node"]
                    self.get_structure(node, user_input["header"])
            elif input_node.identifier.find("_COOKIE") != -1:
                if "header" not in user_input.keys():
                    user_input["header"] = dict()
                if "cookie" not in user_input["header"].keys():
                    user_input["header"]["cookie"] = dict()
                for node_field_sig in input_node_fields_sig:
                    node = self.graph.nodes[node_field_sig]["pfg_node"]
                    self.get_structure(node, user_input["header"]["cookie"])
            elif input_node.identifier.find("_FILES") != -1:
                if "file" not in user_input.keys():
                    user_input["file"] = dict()
                for node_field_sig in input_node_fields_sig:
                    node = self.graph.nodes[node_field_sig]["pfg_node"]
                    self.get_structure(node, user_input["file"])
        return user_input
    
    def is_different(self, PFG):
        # 判断两个PFG是否存在差异(用于计算是否到达了不动点)
        # if len(self.nodes) != len(PFG.nodes):
        if len(self.graph.nodes) != len(PFG.graph.nodes):
            return True
        else:
            # for node1, node2 in zip(self.nodes, PFG.nodes):
            nodes_set1 = list(nx.get_node_attributes(self.graph, 'pfg_node').values())
            nodes_set2 = list(nx.get_node_attributes(PFG.graph, 'pfg_node').values())
            for node1, node2 in zip(nodes_set1, nodes_set2):
                if (node1.pfg_id != node2.pfg_id or node1.code_block_id != node2.code_block_id or 
                    node1.node_type != node2.node_type or node1.parent_type != node2.parent_type or 
                    node1.parent_identifier != node2.parent_identifier or node1.parent_signature != node2.parent_signature or 
                    node1.own_type != node2.own_type or node1.identifier != node2.identifier or 
                    node1.value != node2.value or node1.signature != node2.signature or 
                    node1.short_signature != node2.short_signature or node1.is_class != node2.is_class or 
                    # node1.is_taint != node2.is_taint or node1.points2sets != node2.points2sets or node1.fields != node2.fields
                    node1.status != node2.status or self.get_points2_sig(node1) != self.get_points2_sig(node2) or self.get_fields_sig(node1) != self.get_fields_sig(node2)
                ):
                    return True
        return False

if __name__ == "__main__":
    PFG = PointerFlowGraph()
    node0 = PFGNode(code_block_id = 0, identifier = "$_COOKIE",value = None)
    node1 = PFGNode(code_block_id = 0, identifier = "a",value = None)
    node2 = PFGNode(code_block_id = 0, identifier = "a_1",value = None)
    node3 = PFGNode(code_block_id = 0, identifier = "a_2",value = "a_2")
    node4 = PFGNode(code_block_id = 0, identifier = "a_3",value = None)
    node5 = PFGNode(code_block_id = 0, identifier = "a_1_1",value = 1)
    node6 = PFGNode(code_block_id = 0, identifier = "a_1_2",value = "a_1_2")
    node7 = PFGNode(code_block_id = 0, identifier = "b",value = None)
    node8 = PFGNode(code_block_id = 0, identifier = "b_1",value = 3)
    node9 = PFGNode(code_block_id = 0, identifier = 6,value = "b_1_1")
    node10 = PFGNode(code_block_id = 0, identifier = 1,value = "b_1_2")
    node11 = PFGNode(code_block_id = 0, identifier = "name1", value = "test name1")
    node12 = PFGNode(code_block_id = 0, identifier = "name2", value = None)
    nodes = [node0, node1, node2, node3, node4, node5, node6, node7, node8, node9, node10, node11, node12]
    for node in nodes:
        PFG.add_node(node)
    PFG.add_field_edge(node0, node1)
    PFG.add_field_edge(node0, node7)
    PFG.add_field_edge(node1, node2)
    PFG.add_field_edge(node1, node3)
    PFG.add_field_edge(node1, node4)
    PFG.add_field_edge(node2, node5)
    PFG.add_field_edge(node2, node6)
    PFG.add_field_edge(node7, node8)
    PFG.add_field_edge(node8, node9)
    PFG.add_field_edge(node8, node10)
    PFG.add_data_flow_edge(node4, node11)
    PFG.add_data_flow_edge(node4, node12)
    # user_input = PFG.get_user_input_structure()
    # with open("/home/leousum/AutoPoC/user_input.json", "w", encoding = "utf-8") as f:
    #     json.dump(user_input, f, ensure_ascii = False, indent = 4)