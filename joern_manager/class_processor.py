from typing import List

from joern_manager.array_processor import ArrayProcessor
from joern_manager.cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class ClassProcessor(ArrayProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level = 0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def find_field_use_nodes_in_class(self, class_full_name: str, field_code: str):
        '''
        找到类中某一Field的所有访问节点 E.g. this.pool
        '''
        if not class_full_name or not field_code:
            return []

        nodes = self.find_nodes(
            cpg_type = NodeType.TYPE_DECL,
            conditions = [f'node.{NodeField.FULL_NAME}=="{class_full_name}"'],
            restricts = [NodeField.AST, NodeConstraint.IS_CALL, f'{NodeMethod.FILTER}(node=>node.{NodeField.CODE}=="{field_code}")']
        )
        field_use_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return field_use_nodes

    def get_class_inFile(self, file_path):
        '''
        获取指定文件中的所有Class信息列表
        '''
        cpg_nodes: list = self.get_all_className_within_file_byJoern(file_path)
        ret = list()
        for cpg_node in cpg_nodes:
            if not isinstance(cpg_node, dict):
                continue

            class_info = dict()
            full_name: str = cpg_node.get(NodeField.FULL_NAME, None)
            if full_name is None:
                continue

            class_name = full_name.split(".")[-1]
            package = full_name.replace("." + class_name, "")

            class_info['fullName'] = full_name
            class_info['class_name'] = class_name
            class_info['package'] = package
            class_info['scope'] = (cpg_node.get(NodeField.LINE_NUMBER, None), None)
            class_info['astParentFullName'] = cpg_node.get(NodeField.AST_PARENT_FULL_NAME, None)
            class_info['cpg_id'] = cpg_node.get(NodeField.ID, None)
            next_index = cpg_nodes.index(cpg_node)
            if len(cpg_nodes) > next_index + 1:
                next_cpg = cpg_nodes[next_index+1]
                if isinstance(next_cpg, dict) and next_cpg.get(NodeField.LINE_NUMBER, -1) > cpg_node.get(NodeField.LINE_NUMBER, -1):
                    class_info['scope'] = (cpg_node.get(NodeField.LINE_NUMBER, -1), next_cpg.get(NodeField.LINE_NUMBER, -1) - 1)

            ret.append(class_info)
        return ret

    def find_class_nodes_with_filename(self, file_path: str):
        '''
        根据文件路径找到相应的文件CPG Nodes
        '''
        if not file_path:
            return []
        
        nodes = self.find_nodes(
            cpg_type = NodeType.TYPE_DECL,
            conditions = [f'node.{NodeField.FILE_NAME}=="{file_path}" && ! node.{NodeField.FULL_NAME}.{NodeMethod.CONTAINS}("$")'],
            restricts = []
        )
        class_nodes= [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return class_nodes

    def find_belong_class(self, cpg_node: dict):
        '''
        找到语句所属的 Class CPG Node
        '''
        if isinstance(cpg_node, dict):
            label = cpg_node.get(NodeField.LABEL, None)
            cpg_id = cpg_node.get(NodeField.ID, None)
            call_cpg_node = cpg_node
            ast_in_nodes = []
            if label == NodeLabel.MEMBER:
                ast_in_nodes = self.find_astParent(cpg_node)
            elif label == NodeLabel.METHOD:
                ast_in_nodes = self.find_nodes(
                    cpg_type = NodeType.ALL,
                    conditions = [f"node.{NodeField.ID}=={str(cpg_id)}"],
                    restricts = [NodeField.AST_IN]
                )
            else:
                if label != NodeLabel.CALL:
                    call_cpg_node = self.find_astParent_until_call_or_control(cpg_node)
                if isinstance(call_cpg_node, dict):
                    cpg_id = call_cpg_node.get(NodeField.ID, None)
                    if cpg_id:
                        ast_in_nodes = self.find_nodes(
                            cpg_type = NodeType.CALL,
                            conditions = [f"node.{NodeField.ID}=={str(cpg_id)}"],
                            restricts = [NodeField.DOMINATED_BY, NodeConstraint.IS_METHOD, f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})", NodeField.AST_IN]
                        )
            
            if isinstance(ast_in_nodes, list):
                for node in ast_in_nodes:
                    if isinstance(node, dict) and node.get(NodeField.LABEL, None) == NodeLabel.TYPE_DECL:
                        return node
        return None

    def get_type_decl_nodes_by_name(self, class_name: str):
        '''
        根据类名称获取Class对应的CPG Node
        '''
        class_cpg_nodes = list()
        if class_name:
            nodes = self.find_nodes(
                cpg_type = NodeType.TYPE_DECL,
                conditions = [f'node.{NodeField.NAME}=="{class_name}"'],
                restricts = []
            )
            for node in nodes:
                if isinstance(node, dict) and NodeField.ID in node.keys():
                    class_cpg_nodes.append(node)
        return class_cpg_nodes

    def find_parent_class_name(self, receiver_name: str):
        # 找到类的父类名称
        parent_names = self.find_nodes(
            cpg_type = NodeType.TYPE_DECL,
            conditions = [f'node.{NodeField.FULL_NAME}=="{receiver_name}" || node.{NodeField.NAME}=="{receiver_name}"'],
            restricts = [NodeField.INHERITS_FROM_TYPEFULLNAME]
        )
        return parent_names

    def find_subclass_nodes(self, type_info: any):
        '''
        获取类的子类节点
        '''
        type_name = None
        if isinstance(type_info, str):
            type_name = type_info
        elif isinstance(type_info, dict):
            type_name = type_info.get(NodeField.FULL_NAME, None)
        if type_name is None:
            return []

        nodes = self.find_nodes(
            cpg_type = NodeType.TYPE_DECL,
            conditions = [f'node.{NodeField.INHERITS_FROM_TYPEFULLNAME}.{NodeMethod.CONTAINS}("{type_name}")'],
            restricts = []
        )
        subclass_nodes= [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return subclass_nodes

    def find_inherits_from_out(self, cpg_node: dict):
        '''
        获取类直接继承的父类的信息,传入的cpg_node可以是METHOD和TYPE_DECL两种类型的节点
        '''
        # TODO: 暂时只考虑单继承关系
        if isinstance(cpg_node, dict):
            node_id = cpg_node.get(NodeField.ID, None)
            node_label = cpg_node.get(NodeField.LABEL, None)
            if node_id is None or node_label is None or node_label not in [NodeLabel.METHOD, NodeLabel.TYPE_DECL]:
                return None

            nodes = self.find_nodes(
                cpg_type = NodeType.METHOD if node_label == NodeLabel.METHOD else NodeType.TYPE_DECL,
                conditions = [f'node.{NodeField.ID}=={node_id}'],
                restricts = [NodeField.AST_IN, NodeField.INHERITS_FROM_OUT] if node_label == NodeLabel.METHOD else [NodeField.INHERITS_FROM_OUT]
            )
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict) and NodeField.FULL_NAME in node.keys():
                        return node
        return None

    def is_member_cpg_node(self, cpg_node: dict):
        '''
        判断CPG Node是否是一个MEMBER类型的CPG Node
        '''
        cpg_label = cpg_node.get(NodeField.LABEL, None) if isinstance(cpg_node, dict) else None
        return cpg_label == NodeLabel.MEMBER

    def find_member_usage_cpg_nodes(self, member_cpg_node: dict):
        '''
        找到一个MEMBER节点在哪些语句中被使用
        '''
        # 获取属性名称
        member_name = member_cpg_node.get(NodeField.NAME, None) if isinstance(member_cpg_node, dict) else None
        if member_name is None:
            return []
        
        # 获取此节点所属的类,从而拿到相对路径
        class_node = self.find_belong_class(member_cpg_node)
        class_file_name = class_node.get(NodeField.FILE_NAME, None) if isinstance(class_node, dict) else None
        if class_file_name is None:
            return []

        # 过滤条件:相对路径和代码
        nodes = self.find_nodes(
            cpg_type = NodeType.CALL,
            conditions = [f'node.{NodeField.LOCATION}.{NodeField.FILE_NAME}=="{class_file_name}"', f'node.{NodeField.CODE}=="this.{member_name}" && node.{NodeField.METHOD_FULL_NAME}=="{NodeOperator.FieldAccess}"'],
            restricts = []
        )
        member_usage_cpg_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
        return member_usage_cpg_nodes

    def get_all_parent_class_name(self, receiver_name: str):
        '''
        获取一个类的所有父类
        '''
        all_class_names = list()
        processed_names = list()
        processed_names.append(receiver_name)

        parent_names = self.find_parent_class_name(receiver_name)
        if parent_names:
            all_class_names.extend(parent_names)
            for parent_name in parent_names:
                if parent_name not in processed_names:
                    all_class_names.extend(self.get_all_parent_class_name(parent_name))
                    processed_names.append(parent_name)

        if receiver_name in all_class_names:
            all_class_names.remove(receiver_name)
        all_class_names = list(set(all_class_names))
        return all_class_names

    def get_all_super_class_cpg_nodes(self, class_name: str):
        '''
        获取类的所有父类的CPG Nodes
        '''
        all_super_class_nodes: List[dict] = list()
        if class_name:
            all_super_class_names = self.get_all_parent_class_name(class_name)
            for super_class_name in all_super_class_names:
                all_super_class_nodes.extend(self.get_type_decl_nodes_by_name(super_class_name))
            all_super_class_nodes = self.remove_duplicate_nodes(all_super_class_nodes)
        return all_super_class_nodes

    def get_all_className_within_file_byJoern(self, file_path):
        result_nodes = self.find_class_nodes_with_filename(file_path)
        query_stmt = []
        query_stmt.append(f"""val targetFile = cpg.{NodeType.FILE}.{NodeField.NAME}("{file_path}").head""")
        query_stmt.append(f"""targetFile.{NodeType.TYPE_DECL}""")
        if not isinstance(result_nodes, list) or not result_nodes:
            # TODO: 此处未比较两种语句有什么区别,未来可以删除上面那种语句
            result_nodes = self.query(query_stmt)
        return result_nodes

    def joern_client_query_for_field_by_classname(self, class_full_name):
        field_query = f"""cpg.{NodeType.TYPE_DECL}.{NodeField.FULL_NAME}("{class_full_name}").{NodeType.MEMBER}.toJson"""
        nodes = list()
        try:
            query_result = self.joern_client.execute(field_query)["stdout"]
            query_result = query_result[query_result.find("=") + 1:].strip()
            nodes = self.str2list(query_result)
            # self.log_manager.log_info(f"CPG Query Success: {field_query}", False, self.indent_level) # 记得恢复
        except Exception as e:
            nodes = list()
            self.log_manager.log_info(f"CPG Query Fail: {field_query}", False, self.indent_level)
            raise (e)
        return nodes