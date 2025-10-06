from source_sink_processor import SourceSinkProcessor
from cpg_field import NodeType, NodeField, NodeMethod

class IOServer(SourceSinkProcessor):
    def __init__(self, server_point, repo_path, log_manager, indent_level=0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

    def find_possible_read_method_fullnames(self, table_name: str):
        '''
        查找所有读取表数据的方法名称
        '''
        fullnames = list()
        # (1) 以"select" + 表名称为关键字搜索可能的读取操作语句
        restrict = f'{NodeMethod.FILTER}(node => (node.{NodeField.CODE}.contains("select") && node.{NodeField.CODE}.contains("{table_name}")))'
        read_nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [],
            restricts = [restrict, f"{NodeMethod.SORT_BY}(node => node.{NodeField.LINE_NUMBER})", f"{NodeMethod.MAP}(x=> (x.node.{NodeField.ID}, x.node.{NodeField.LOCATION}.{NodeField.FILE_NAME}, x.node.{NodeField.LOCATION}.{NodeField.LINE_NUMBER}))", "take(26)"]
        )
        if read_nodes:
            for i in range(0, len(read_nodes)):
                if isinstance(read_nodes[i], dict):
                    read_nodes[i][NodeField.ID] = read_nodes[i]["_1"]
                    read_nodes[i][NodeField.FILE_NAME] = read_nodes[i]["_2"]
                    read_nodes[i][NodeField.LINE_NUMBER] = read_nodes[i]["_3"]
                    del read_nodes[i]["_1"]
                    del read_nodes[i]["_2"]
                    del read_nodes[i]["_3"]
        # (2) 找到每一条读取语句所处的函数
        processed = list()
        for read_node in read_nodes:
            if isinstance(read_node, dict):
                file_line = read_node[NodeField.FILE_NAME] + "_" + str(read_node[NodeField.LINE_NUMBER])
                if file_line not in processed:
                    processed.append(file_line)
                    belong_method_node = self.find_belong_method(read_node)
                    if belong_method_node is not None and isinstance(belong_method_node, dict):
                        if NodeField.FULL_NAME in belong_method_node.keys():
                            if belong_method_node[NodeField.FULL_NAME] not in fullnames:
                                fullnames.append(belong_method_node[NodeField.FULL_NAME])
        return fullnames