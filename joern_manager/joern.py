import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)

import config
from joern_manager.io_processor import IOServer
from joern_manager.cpg_field import NodeField
from utils.log_manager import LogManager

class JoernServer(IOServer):
    def __init__(self, server_point, repo_path, log_manager, indent_level=0):
        super().__init__(server_point, repo_path, log_manager, indent_level)

if __name__ == "__main__":
    # 初始化
    log_manager = LogManager("test", "test")
    joern_server = JoernServer(
        server_point = config.JOERN_SERVER_POINT,
        repo_path = os.path.join(project_root, "test"),
        log_manager = log_manager,
        indent_level = 0
    )

    # 选定分析Entry
    start_cpg_nodes = joern_server.find_cfg_node_by_contain("Student s1 = new Student()", None) # test_case.java第31行的赋值语句
    start_cpg_node = None
    if start_cpg_nodes:
        start_cpg_node = start_cpg_nodes[0]
    workstack = list()
    if isinstance(start_cpg_node, dict):
        workstack.append(start_cpg_node)

    visited = list()
    while workstack != []:
        node = workstack.pop()
        if isinstance(node, dict):
            node_id = node.get(NodeField.ID, None)
            if node_id and node_id not in visited:
                visited.append(node_id)
                stmt = joern_server.parse_stmt(node)
                if stmt is not None:
                    print(stmt.to_string())
                    input()
                successors = joern_server.find_cfg_successors(node)
                for successor in successors:
                    if isinstance(successor, dict):
                        workstack.append(successor)
    joern_server.close_cpg()