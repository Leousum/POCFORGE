import os
import sys
import json
import time
import shutil
import hashlib
import subprocess
from typing import List

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)
sys.path.append(os.path.join(project_root, "joern_manager"))

import config
from utils.log_manager import LogManager
from cpgql.client import CPGQLSClient
from cpgql.queries import import_code_query, import_cpg_query, open_project, delete_project, close_query, exit_joern
from cpg_field import NodeType, NodeField, NodeConstraint, NodeMethod, NodeLabel, NodeOperator

class BaseServer():
    def __init__(self, server_point: str, repo_path: str, log_manager: LogManager, indent_level: int = 0):
        # 基础信息
        self.repo_path = repo_path
        self.log_manager = log_manager
        self.indent_level = indent_level
        self.project_name = None
        self.init_base_info()

        self.joern_client = None
        self.joern_query_count = 0 # Joern查询次数
        self.joern_query_limit = config.JOERN_MAX_QUERY_LIMIT
        self.joern_server_point = server_point
        self.joern_workspace_path = config.JOERN_WORKSPACE_PATH
        self.joern_construct_try_num = 3 # 剩余可尝试构建CPG次数,设为属性以避免出现无限循环

        self.isPatched = server_point == config.JOERN_SERVER_POINT
        # 临时文件路径
        self.cpg_path = os.path.join(self.joern_workspace_path, self.project_name, "cpg.bin")
        self.type_map_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "cpgql", "type_map.json")
        self.all_types_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "cpgql", "all_types.json")
        self.query_result_path = os.path.join(config.JOERN_QUERY_ROOT, self.project_name)
        
        # 分析CPG Node所需信息
        self.type_map = dict()
        self.all_types = list() # 所有类型列表
        self.variable_types = list() # 变量类型列表
        
        # 预处理
        self._preprocess()

    def init_base_info(self):
        repo_name = self.repo_path.split(os.sep)[-1]
        if repo_name:
            self.project_name = repo_name

    def is_not_empty_file(self, file_path: str):
        if file_path:
            if os.path.exists(file_path):
                return os.path.getsize(file_path) > 0
        return False

    def get_project_name(self):
        return self.project_name
     
    def _preprocess(self):
        '''
        预处理阶段
        '''
        # (0) 构建代码属性图前的准备: 启动Joern服务,删除构建失败的CPG项目
        start_time = time.time()
        success_import_cpg_flag = False # 是否成功导入CPG

        self.start_joern_service(self.joern_server_point)
        self.joern_client = CPGQLSClient(self.joern_server_point)
        self.log_manager.log_info(f'Construct Initial CPG...', False, self.indent_level)

        if not os.path.exists(self.query_result_path):
            os.makedirs(self.query_result_path, mode = 0o777)

        if os.path.exists(self.cpg_path) and not self.is_not_empty_file(self.cpg_path):
            # 当发现此前已经构建过CPG文件,但是其内容为空时,就将其删除以重新构建
            self.log_manager.log_info(f'Deleting Invalid CPG Project `{self.project_name}`', False, self.indent_level)
            self.joern_client.execute(delete_project(self.project_name)) # 此处不推荐使用shutil.rmtree

        if os.path.exists(self.cpg_path) and self.is_not_empty_file(self.cpg_path):
            self.log_manager.log_info(f'Project with name `{self.project_name}` already exists', False, self.indent_level)

            # (1) 使用 `open` 命令打开现有的CPG文件
            if not success_import_cpg_flag and self.joern_construct_try_num > 0:
                self.joern_construct_try_num -= 1
                self.joern_client.execute(open_project(self.project_name))
                success_import_cpg_flag = self._success_import_cpg()
                if not success_import_cpg_flag:
                    self.log_manager.log_info(f'Open Existing CPG File Failed! [{3 - self.joern_construct_try_num} / 3 attempts]', False, self.indent_level + 1)

            # (2) 使用 `importCpg` 命令复用现有的CPG文件
            if not success_import_cpg_flag and self.joern_construct_try_num > 0:
                self.joern_construct_try_num -= 1
                self.joern_client.execute(import_cpg_query(self.cpg_path))
                success_import_cpg_flag = self._success_import_cpg()
                if not success_import_cpg_flag:
                    self.log_manager.log_info(f'Construct CPG Failed With Existing CPG File! [{3 - self.joern_construct_try_num} / 3 attempts]', False, self.indent_level + 1)
        
        if not success_import_cpg_flag:
            self.log_manager.log_info(f'Creating project `{self.project_name}` for code at `{self.repo_path}`', False, self.indent_level)

            # (3) 使用 `importCode` 命令重新构建CPG文件
            while (not success_import_cpg_flag and self.joern_construct_try_num > 0):
                self.joern_construct_try_num -= 1
                self.joern_client.execute(import_code_query(self.repo_path, self.project_name))
                success_import_cpg_flag = self._success_import_cpg()
                if not success_import_cpg_flag:
                    self.log_manager.log_info(f'Construct CPG Failed! [{3 - self.joern_construct_try_num} / 3 attempts]', False, self.indent_level + 1)
                    if self.joern_construct_try_num > 0:
                        self.log_manager.log_info(f'Attempting to Rebuild CPG!', False, self.indent_level + 1)
        
        assert success_import_cpg_flag, f"Build CPG Failed! (tried it {3 - self.joern_construct_try_num} times)"
        self.log_manager.log_info(f'Construct CPG Success!', False, self.indent_level)
        self.log_manager.log_cost("construct_cpg_time", time.time() - start_time)
        self.joern_construct_try_num = 3 # 成功构建CPG时,恢复剩余尝试构建次数
        
        # 建立相关文件夹/加载配置信息
        # if os.path.exists(self.query_result_path):
        #     shutil.rmtree(self.query_result_path) # 删除历史查询缓存信息
        with open(self.type_map_path, "r", encoding = "utf-8") as f:
            self.type_map = json.load(f)
        self.variable_types = list(self.type_map.keys())
        with open(self.all_types_path, "r", encoding = "utf-8") as f:
            self.all_types = json.load(f)
            
    def start_joern_service(self, server_point):
        try:
            # 切换到Joern_WorkSpace所在的目录下,使得CPG能够存储到预期位置
            joern_work_dir = os.path.dirname(self.joern_workspace_path)
            if not os.path.exists(joern_work_dir):
                os.makedirs(joern_work_dir, mode = 0o777)
            os.chdir(joern_work_dir)
            # Run command in background without displaying any output
            port = server_point[server_point.find(":") + 1:]
            command = ["joern", "--server", "--server-host", "localhost", "--server-port", port] # "-J-Xmx10G"
            subprocess.Popen(command, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL, start_new_session = True)
            # Wait until the Joern service start to prevent subsequent processes from being affected
            time.sleep(10)
            self.log_manager.log_info(f"Joern Service Start Successfully! [server point: {server_point}]", False, self.indent_level)
        except:
            self.log_manager.log_info(f"Joern Service Start Failed! [server point: {server_point}]", False, self.indent_level)

    def restart_joern_service(self):
        try:
            # (0) 重启前的准备: 关闭Joern服务、重启Joern服务,删除构建失败的CPG项目
            self.close_cpg(False)
            self.joern_query_count = 0
            self.start_joern_service(self.joern_server_point)
            self.joern_client = CPGQLSClient(self.joern_server_point)
            self.log_manager.log_info(f'Restarting CPG...', False, self.indent_level)
            success_import_cpg_flag = False # 是否成功导入CPG

            if os.path.exists(self.cpg_path) and not self.is_not_empty_file(self.cpg_path):
                # 当发现此前已经构建过CPG文件,但是其内容为空时,就将其删除以重新构建
                self.log_manager.log_info(f'Deleting Invalid CPG Project `{self.project_name}`', False, self.indent_level)
                self.joern_client.execute(delete_project(self.project_name))

            if os.path.exists(self.cpg_path) and self.is_not_empty_file(self.cpg_path):
                self.log_manager.log_info(f'Project with name `{self.project_name}` already exists', False, self.indent_level)

                # (1) 使用 `open` 命令打开现有的CPG文件
                if not success_import_cpg_flag and self.joern_construct_try_num > 0:
                    self.joern_construct_try_num -= 1
                    self.joern_client.execute(open_project(self.project_name))
                    success_import_cpg_flag = self._success_import_cpg()
                    if not success_import_cpg_flag:
                        self.log_manager.log_info(f'Open Existing CPG File Failed! [{3 - self.joern_construct_try_num} / 3 attempts]', False, self.indent_level + 1)

                # (2) 使用 `importCpg` 命令复用现有的CPG文件
                if not success_import_cpg_flag and self.joern_construct_try_num > 0:
                    self.joern_construct_try_num -= 1
                    self.joern_client.execute(import_cpg_query(self.cpg_path))
                    success_import_cpg_flag = self._success_import_cpg()
                    if not success_import_cpg_flag:
                        self.log_manager.log_info(f'Construct CPG Failed With Existing CPG Filed! [{3 - self.joern_construct_try_num} / 3 attempts]', False, self.indent_level + 1)

            if not success_import_cpg_flag:
                self.log_manager.log_info(f'Creating project `{self.project_name}` for code at `{self.repo_path}`', False, self.indent_level)

                # (3) 使用 `importCode` 命令重新构建CPG文件
                while (not success_import_cpg_flag and self.joern_construct_try_num > 0):
                    self.joern_construct_try_num -= 1
                    self.joern_client.execute(import_code_query(self.repo_path, self.project_name))
                    success_import_cpg_flag = self._success_import_cpg()
                    if not success_import_cpg_flag:
                        self.log_manager.log_info(f'Construct CPG Failed! [{3 - self.joern_construct_try_num} / 3 attempts]', False, self.indent_level + 1)
                        if self.joern_construct_try_num > 0:
                            self.log_manager.log_info(f'Attempting to Rebuild CPG!', False, self.indent_level + 1)

            assert success_import_cpg_flag, f"Build CPG Failed! (tried it {self.joern_construct_try_num} times)"
            self.log_manager.log_info(f'Restart Joern Service Success! [server point: {self.joern_server_point}]', False, self.indent_level)
            self.joern_construct_try_num = 3 # 成功重启时,恢复剩余尝试构建次数
        except Exception as e:
            self.log_manager.log_info(f"Joern Service Restart Failed! [server point: {self.joern_server_point}]", False, self.indent_level)
            raise(e)
        
    def close_cpg(self, clean_history_query = True):
        try:
            # if clean_history_query:
            #     if os.path.exists(self.query_result_path):
            #         shutil.rmtree(self.query_result_path)
            self.joern_client.execute(close_query(self.project_name))
            self.joern_client.execute(exit_joern())
            time.sleep(10)
        except:
            pass
        self.log_manager.log_info(f"Joern Service Shut Down Successfully! [server point: {self.joern_server_point}] [project: {self.project_name}]", False, self.indent_level)

    def query(self, queries: list):
        query_except_last = queries[:-1]
        for query in query_except_last:
            try:
                self.joern_client.execute(query)
                # self.log_manager.log_info(f"Define Variable Success: {query}", False, self.indent_level) # 记得恢复
            except Exception as e:
                # self.log_manager.log_info(f"Define Variable Fail: {query}", False, self.indent_level) # 记得恢复
                raise (e)
        query_last = queries[-1]
        query_last += ".toJson"
        nodes = []
        try:
            # Joern查询次数达到2600次以上时就会崩溃,下面的代码用于自动重启Joern服务
            if self.joern_query_count >= self.joern_query_limit:
                self.restart_joern_service()
            query_result = None
            try:
                query_result = self.joern_client.execute(query_last)["stdout"]
            except:
                self.restart_joern_service()
                query_result = self.joern_client.execute(query_last)["stdout"]
            # print(f"query result: {str(query_result)}") # 记得删除
            self.joern_query_count += 1
            query_result = query_result[query_result.find("=") + 1:].strip()
            nodes = self.str2list(query_result)
            # self.log_manager.log_info(f"CPG Query Success: {query_last}", False, self.indent_level) # 记得恢复
        except Exception as e:
            nodes = list()
            self.log_manager.log_info(f"CPG Query Fail: {query_last}", False, self.indent_level)
            raise(e)
        nodes = self.remove_duplicate_nodes(nodes)
        return nodes

    def get_query_hash(self, input_string: str) -> str:
        '''
        使用多种加密算法,获取每种算法的哈希值,用于标识查询语句
        '''
        hash_md5 = hashlib.md5(input_string.encode()).hexdigest() # MD5哈希码: 32位
        hash_sha1 = hashlib.sha1(input_string.encode()).hexdigest() # SHA1哈希码: 40位
        hash_sha256 = hashlib.sha256(input_string.encode()).hexdigest() # SHA256哈希码: 64位
        # 拼接多个哈希值
        final_hash = f"{hash_md5}-{hash_sha1}-{hash_sha256}"
        return final_hash

    def find_nodes(self, cpg_type: str, conditions: list, restricts: list, query_statement: any = None):
        '''
        Find nodes based on the condition
        '''
        query = ""
        if query_statement is not None:
            query = query_statement
        else:
            query = "cpg." + cpg_type
            for condition in conditions:
                query += f'.{NodeMethod.FILTER}(node => {condition})'
            for restrict in restricts:
                query += f'.{restrict}'
            query += ".toJson"
        nodes = list()
        is_queried = False
        # print(f"Query: {query}") # 记得删除
        query_hash = self.get_query_hash(query)
        query_file_path = os.path.join(self.query_result_path, query_hash + ".json")
        # query_file_path = os.path.join(self.query_result_path, query.replace(".", "_").replace(" ", "").replace("/", "_") + ".json")
        if os.path.exists(query_file_path) and query != f"cpg.{NodeType.CALL}.{NodeMethod.MAP}( x=> (x.node.{NodeField.ID}, x.node.{NodeField.CODE})).take(2).toJson":
            try:
                with open(query_file_path, "r", encoding = "utf-8") as f:
                    nodes = json.load(f)
                if isinstance(nodes, list) and ((nodes != [] and not str(nodes[0]).startswith("1.4.200/4]")) or nodes == []):
                    is_queried = True
            except:
                nodes = list()
        if not is_queried:
            try:
                # 2024年10月10日发现: Joern查询次数达到2600次以上时就会崩溃,我们需要自动重启Joern服务
                if self.joern_query_count >= self.joern_query_limit:
                    self.restart_joern_service()
                query_result = None
                try:
                    query_result = self.joern_client.execute(query)["stdout"]
                except:
                    self.restart_joern_service()
                    query_result = self.joern_client.execute(query)["stdout"]
                self.joern_query_count += 1
                # print(f"query result: {str(query_result)}") # 记得删除
                query_result = query_result[query_result.find("=") + 1:].strip()
                nodes = self.str2list(query_result)
                # self.log_manager.log_info(f"CPG Query Success: {query}", False, self.indent_level)  # 记得恢复
                try:
                    if isinstance(nodes, list) and ((nodes != [] and not str(nodes[0]).startswith("1.4.200/4]")) or nodes == []):
                        with open(query_file_path, "w", encoding = "utf-8") as f:
                            json.dump(nodes, f, ensure_ascii = False, indent = 4)
                except:
                    pass
            except Exception as e:
                nodes = list()
                self.log_manager.log_info(f"CPG Query Fail: {query}", False, self.indent_level)
                raise(e)
        return nodes

    def _success_import_cpg(self):
        '''
        检查CPG文件是否成功导入
        '''
        try:
            nodes = self.find_nodes(
                cpg_type = NodeType.CALL,
                conditions = [],
                restricts = [f"{NodeMethod.MAP}( x=> (x.node.{NodeField.ID}, x.node.{NodeField.CODE}))", "take(2)"]
            )
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        return True
            return False
        except:
            return False

    # Extract a list from a string
    def string2dictlist(self, text):
        result = list()
        if text.find("[") != -1 and text.find("]") != -1 and text.find("{") != -1 and text.find("}") != -1:
            text = text.strip("[]").replace("\\", "").replace('\"', "'").replace('"', "'")
            content_dicts = text.split("},{")
            for content_dict in content_dicts:
                content_dict = content_dict.strip("{}")
                content = dict()
                key_values = content_dict.split(",'")
                last_k = None
                for key_value in key_values:
                    if key_value.find(":") != -1:
                        k_v_list = key_value.split("':")
                        if len(k_v_list) >= 2:
                            k = key_value.split("':")[0].strip("'")
                            v = key_value.split("':")[1].strip("'")
                            if v.startswith("[") and v.endswith("]"):
                                v = v.strip("[]").split(",")
                                if v == ['']:
                                    v = []
                            if k in [NodeField.ID, NodeField.ORDER, NodeField.LINE_NUMBER, NodeField.ARGUMENT_INDEX]:
                                v = int(v)
                            content[k] = v
                            last_k = k
                    else:
                        if last_k is not None:
                            if isinstance(content[last_k], str) and isinstance(key_value, str):
                                content[last_k] += key_value
                            if isinstance(content[last_k], str) and content[last_k].startswith("[") and content[last_k].endswith("]"):
                                try:
                                    content[last_k] = json.loads(content[last_k])
                                except:
                                    try:
                                        content[last_k] = content[last_k].strip("[]").split(",")
                                        if content[last_k] == ['']:
                                            content[last_k] = []
                                    except:
                                        pass
                if content != {}:
                    result.append(content)
        else:
            text = text.strip("[]").replace("\\", "").replace('\"', "'").replace('"', "'")
            result = text.split(",")
            for i in range(0, len(result)):
                result[i] = result[i].strip("'").strip('"')
        return result

    # Extract a list from a string
    def str2list(self, text):
        text_list = list()
        try:
            if text.find("[") != -1 and text.rfind("]") != -1:
                text = text[text.find("["):text.rfind("]") + 1]
                try:
                    # 替换特殊字符
                    input_string = text
                    if text and text != '[]':
                        special_strs = [f'joern special chars{i}' for i in range(3)]
                        characters_pairs = {'\r': '', '\n': '', '\t': '', '\b': '', '\f': '',
                                            '\\\\\\"': special_strs[0], '(\\"': special_strs[1], '\\")': special_strs[2], '\\"': '"',
                                            special_strs[0]: '\\"', special_strs[1]: '(\\"', special_strs[2]: '\\")'}
                        for k, v in characters_pairs.items():
                            input_string = input_string.replace(k, v)
                    # 删除旧文件
                    json_file_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "temp.json")
                    if os.path.exists(json_file_path):
                        os.remove(json_file_path)
                    # 存入json文件
                    with open(json_file_path, "w", encoding = "utf-8") as json_file:
                        json_file.write(input_string)
                    # 从json文件读取内容
                    if os.path.exists(json_file_path):
                        with open(json_file_path, 'r', encoding = "utf-8") as json_file:
                            result = json.load(json_file)
                            if isinstance(result, list):
                                return result
                except:
                    pass
                infos = text.split("\n")
                text = "".join(infos).strip()
                text_list = json.loads(text.replace("\\", ""))
        except:
            try:
                text_list = self.string2dictlist(text)
            except Exception as e:
                print(f"*{text}*")
                # raise(e)
        return text_list

    def remove_duplicate_nodes(self, nodes: list):
        node_ids = []
        new_nodes = []
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict) and NodeField.ID in node.keys():
                    if node[NodeField.ID] not in node_ids:
                        node_ids.append(node[NodeField.ID])
                        new_nodes.append(node)
        return new_nodes

    # ===================================================== General Approach Start =====================================================

    def content_to_num(self, content: any):
        '''
        获取数字
        '''
        return int(content) if ( isinstance(content, str) and content.isdigit() ) else ( content if isinstance(content, int) else 0 )

    def get_lineNumber(self, cpg_node: dict):
        '''
        获取行号
        '''
        if not isinstance(cpg_node, dict):
            return None

        lineNumber = cpg_node.get(NodeField.LINE_NUMBER, None)
        try:
            lineNumber = int(str(lineNumber).replace("\\", "").replace("\"", "").replace("\'", ""))
        except:
            lineNumber = None
        return lineNumber
    
    def find_cpg_node_by_id(self, cpg_id):
        nodes = self.find_nodes(
            cpg_type = NodeType.ALL,
            conditions = [f"node.{NodeField.ID}=={str(cpg_id)}"],
            restricts = []
        )
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    return node
        return None

    def find_cpg_call_nodes_by_code(self, code: str):
        '''
        根据代码查找所有CPG Nodes
        '''
        cpg_nodes: List[dict] = []
        if code:
            # 删除代码中的
            while code.find('"') != -1:
                mark1 = code.find('"')
                mark2 = code.rfind('"')
                if mark1 != mark2:
                    code = code[mark1 + 1:mark2]
                else:
                    code1 = code[:mark1]
                    code2 = code[mark1 + 1:]
                    if len(code1) > len(code2):
                        code = code1
                    else:
                        code = code2
            code = code.strip("\\\\n").strip("\\\n").strip("\\n").strip()

            if code:
                nodes = self.find_nodes(
                    cpg_type = NodeType.ALL,
                    conditions = [f'node.{NodeField.CODE}.{NodeMethod.CONTAINS}("{code}")'],
                    restricts = [f'{NodeMethod.FILTER}(node => ! node.{NodeField.METHOD_FULL_NAME}.{NodeMethod.CONTAINS}("<operator>."))']
                )
                temp_nodes = [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []
                cpg_nodes.extend(temp_nodes)
        return cpg_nodes

    # ===================================================== General Approach End =====================================================