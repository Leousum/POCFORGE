import os
import json
import time
import psutil
import traceback

from LLM.model_manager import ModelManager
from utils.log_manager import LogManager
from joern_manager.joern import JoernServer
from static_analysis.front_page.front_page_manager import PageManager
from static_analysis.taint.fwd_analysis import ForwardAnalyzer
from static_analysis.taint.bwd_analysis import BackwardAnalyzer
from static_analysis.taint.source_sink_handler import SourceSinkHandler
from reporter import Reporter
import config

class VulnDetector():
    def __init__(self, repo_path: str) -> None:
        self.repo_path = repo_path
        self.config_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "config.json")
        self.config_file = dict()
        with open(self.config_path, "r", encoding = "utf-8") as f:
            self.config_file = json.load(f)
        self.processed_ids = list() # 处理过的CPG ID列表
        self.processed_files = list() # 处理过的文件相对路径列表
        self.redirect_funcs = ["require", "include", "include_once", "require_once"] # TODO:改为从配置文件中读取
        self.log_manager = LogManager(repo_path.strip("/").split("/")[-1], "all")
        self.init_memory = psutil.virtual_memory().used
        self.joern_server = JoernServer(self.config_file, repo_path, self.log_manager)
        self.page_manager = PageManager(self.config_file, self.log_manager)
        self.model_manager = ModelManager(self.config_file, self.log_manager)
        self.s2_handler = SourceSinkHandler(self.joern_server, self.model_manager, self.log_manager)
        self.forward_analyzer = ForwardAnalyzer(self.config_file, self.joern_server, self.page_manager, self.model_manager, self.log_manager, self.s2_handler)
        self.backward_analyzer = BackwardAnalyzer(self.config_file, self.joern_server, self.page_manager, self.model_manager, self.log_manager, self.s2_handler)
        self.entry_num = 0
        self.reporter = Reporter(self.log_manager, os.path.join(self.config_file["report_root"], repo_path.strip("/").split("/")[-1]))
        self.log_manager.log_info(f"Initial memory usage: {self.init_memory/(1024**3):.6f} GB", False, 1, True)
        self.peak_memory = 0
        self.check_memory()

    def check_memory(self):
        # 检查内存使用情况
        virtual_memory = psutil.virtual_memory()
        current_memory = virtual_memory.used
        self.peak_memory = max(self.peak_memory, current_memory)
        self.log_manager.log_info(f"Current memory usage: {current_memory/(1024**3):.6f} GB [Total: {virtual_memory.total/(1024**3):.6f} GB, Available: {virtual_memory.available/(1024**3):.6f} GB]", False, 1, True)
        self.log_manager.log_info(f"Peak memory usage: {self.peak_memory/(1024**3):.6f} GB", False, 1, True)

    def analysis_file(self, node_id: str):
        # 分析文件中的跳转/包含函数
        summary = dict()
        summary["abs_path"] = None
        summary["relative_path"] = None
        summary["redirects"] = []
        summary["redirect_files"] = []
        cpg_node = self.joern_server.find_cpg_call_node_location_by_id(node_id)
        if cpg_node is not None:
            for k in cpg_node.keys():
                relative_path = k
                if relative_path is not None and relative_path not in ["", "N/A"] and relative_path not in self.processed_files:
                    summary["relative_path"] = relative_path
                    self.processed_files.append(relative_path)
                    summary["abs_path"] = os.path.join(self.joern_server.repo_path, relative_path)
                    summary_path = os.path.join(self.joern_server.file_path, relative_path.replace(".","_").replace("/","_").replace("\\","_") + ".json")
                    callsites = self.joern_server.find_callIn_nodes(self.redirect_funcs, relative_path)
                    for callsite in callsites:
                        if callsite is not None and isinstance(callsite, dict):
                            summary["redirects"].append(callsite)
                            if "code" in callsite:
                                if callsite["code"].find(".php") != -1:
                                    try:
                                        code = callsite["code"]
                                        prefix = code[max(0, code.find(" ")):code.rfind(".php") + len(".php")]
                                        reversed_prefix = prefix[::-1]
                                        start = 0
                                        for i in range(0, len(reversed_prefix)):
                                            if reversed_prefix[i] == "'" or reversed_prefix[i] == "\"":
                                                start = len(reversed_prefix) - i
                                                break
                                        summary["redirect_files"].append(prefix[start:])
                                    except:
                                        pass
                    with open(summary_path, "w", encoding = "utf-8") as f:
                        json.dump(summary, f, ensure_ascii = False, indent = 4)

    def analysis_node(self, node_id: str, sources = None):
        # 分析节点
        try:
            num = 0
            candidate_node = self.joern_server.find_astParent_until_top({"id": node_id, "_label": "CALL", "code": None})
            if isinstance(candidate_node, dict):
                if "id" in candidate_node.keys() and candidate_node["id"] not in self.processed_ids:
                    if self.s2_handler.filter_source(sources, candidate_node):
                        entry_infos = self.s2_handler.get_entry_infos(candidate_node)
                        num += len(entry_infos)
                        self.entry_num += len(entry_infos)
                        for entry_info in entry_infos:
                            entry_node = entry_info["entry_node"]
                            call_info = self.backward_analyzer.code_manager.collect_report_codes(entry_info["call_info"])
                            self.reporter.output_report(call_info)
                            # if isinstance(entry_node, dict):
                            #     if "id" in entry_node.keys():
                            #         if candidate_node["id"] not in self.processed_ids:
                            #             self.processed_ids.append(candidate_node["id"])
                            #         self.analysis_file(entry_node["id"])
                            #         self.log_manager.log_info(f'Analyzing Entry:', False, 1, True)
                            #         self.log_manager.log_info(f'Parsing Enrty: {entry_node}', False, 1, True)
                            #         self.log_manager.log_info(f'{self.joern_server.parse_stmt(entry_node).to_string()}', False, 2, True)
                            #         self.forward_analyzer.forward_analysis(start_cpg_node = entry_node, init_call_stmt = None, analyze_all = False, node_id = node_id) # 代码片段默认进行部分分析
            self.log_manager.log_info(f'[Find {str(num)} Entry Points for {node_id}] (Total: {str(self.entry_num)})', False, 0, True)
        except Exception as e:
            self.log_manager.log_info(f'[Error: {e}]: \n{traceback.format_exc()}', False, 1, True)
            raise(e)

    def process_source_files(self):
        # 从source出发执行前向分析
        sources = self.s2_handler.get_sources()
        source_vars, source_funcs = self.s2_handler.get_separate_sources()
        source_ids = list()
        source_ids.extend(self.joern_server.find_source_var_ids(source_vars))
        source_ids.extend(self.joern_server.find_source_func_ids(source_funcs))
        source_ids = list(set(source_ids))
        source_ids, nodes = self.backward_analyzer.sort_nodes(source_ids, "source")
        self.log_manager.log_info(f'Found a Total of {len(source_ids)} Candidate Source Points.', False, 0, True)
        for i in range(0, len(source_ids)):
            self.log_manager.log_info(f'==============================================================', False, 0, True)
            self.log_manager.log_info(f'Analyzing The Source Point[{str(i + 1)}] (sink id: {str(source_ids[i])})', False, 0, True)
            if i >= 0 and i < len(nodes):
                self.log_manager.log_info(f'Analyzing Source Node: {str(nodes[i])}', False, 1, True)
            self.analysis_node(source_ids[i], sources)
            self.check_memory()
        self.log_manager.log_info(f'[Total Entry Points From Sources: {str(self.entry_num)} !]', False, 0, True)
        self.entry_num = 0
    
    def get_vuln_type(self, func_name: str):
        # 获取可能的漏洞类型
        vuln_type = None
        if func_name:
            for short_name in self.backward_analyzer.taint_config["sinks"].keys():
                if func_name.lower() == short_name.lower():
                    item = self.backward_analyzer.taint_config["sinks"][short_name]
                    vuln_type = item["vuln_type"]
        return vuln_type

    def is_valid_source(self, call_info: dict):
        # 检查source是否有效
        invalid_sources = [
            "$_SERVER['SCRIPT_FILENAME']", 
            "$_SERVER['SCRIPT_NAME']", 
            "$_SERVER['argv']", 
            "$_SERVER['REQUEST_METHOD']", 
            "$_SERVER['REMOTE_ADDR']", 
            "$_SERVER['SERVER_ADMIN']",
            "$_SESSION", "PARAM_CLEAN", 
            "PARAM_INT", 
            "PARAM_FLOAT", 
            "PARAM_LOCALISEDFLOAT", 
            "PARAM_SEQUENCE", 
            "PARAM_BOOL", 
            "PARAM_NOTAGS", 
            "PARAM_PLUGIN", 
            "PARAM_AREA", 
            "PARAM_FILE", 
            "PARAM_PATH", 
            "PARAM_HOST", 
            "PARAM_BASE64", 
            "PARAM_CAPABILITY", 
            "PARAM_PERMISSION", 
            "PARAM_AUTH", 
            "PARAM_LANG", 
            "PARAM_THEME",
            "$_FILES['attachments'][$field][$i]",
            "$db->escape_string($mybb->input",
            "$db->fetch_array($query)",
            "$db->simple_select(",
            "$pages",
            "MyBB::INPUT_INT",
            "MyBB::INPUT_FLOAT",
            "MyBB::INPUT_BOOL",
            "MyBB::INPUT_ARRAY"
        ]
        if isinstance(call_info, dict) and "taint_data" in call_info.keys() and "call_stack" in call_info.keys():
            if call_info["taint_data"]:
                for source in invalid_sources:
                    if call_info["taint_data"].lower().find(source.lower()) != -1:
                        return False
                invalid_funcs = ["die_html_input_error()"]
                for item in call_info["call_stack"]:
                    if "codes" in item.keys():
                        for code in item["codes"]:
                            for invalid_func in invalid_funcs:
                                if code.find(invalid_func) != -1:
                                    return False
                return True
            else:
                return False
        return False

    def process_sink_files(self) -> int:
        # 从sink出发执行后向分析
        detected_vul_num = 0
        try:
            sinks = self.s2_handler.get_sinks()
            self.log_manager.log_info(f"Load {len(sinks)} Sink APIs From Config [{str(json.dumps(sinks)).strip('[]')}]", False, 1, True)
            sink_ids = list()
            sink_ids_dir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "sink_ids")
            if not os.path.exists(sink_ids_dir):
                os.makedirs(sink_ids_dir, mode = 0o777)
            sink_ids_path = os.path.join(sink_ids_dir, self.repo_path.strip("/").split("/")[-1] + "_sinkIds.json")
            if os.path.exists(sink_ids_path):
                with open(sink_ids_path, "r", encoding = "utf-8") as f:
                    sink_ids = json.load(f)
            else:
                sink_ids = self.joern_server.find_sink_ids(sinks)
                sink_ids = list(set(sink_ids))
                with open(sink_ids_path, "w", encoding = "utf-8") as f:
                    json.dump(sink_ids, f, ensure_ascii = False, indent = 4)
            # sink_ids, nodes = self.backward_analyzer.sort_nodes(sink_ids, "sink")
            self.log_manager.log_info(f'Found a Total of {len(sink_ids)} Candidate Sink Points.', False, 0, True)
            for i in range(0, len(sink_ids)):
                try:
                    self.log_manager.log_info(f'==============================================================', False, 0, True)
                    t1 = time.time()
                    # if i >= 0 and i < len(nodes):
                    #     self.log_manager.log_info(f'Analyzing Node: {str(nodes[i])}', False, 1, True)
                    if self.log_manager.is_analyzed(sink_ids[i]):
                        continue
                    else:
                        self.log_manager.log_cost("ids", sink_ids[i])
                    self.joern_server.var_identifiers = list()
                    self.joern_server.obj_identifiers = list()
                    func_name, vuln_infos = self.backward_analyzer.backward_analysis(sink_ids[i], i)
                    vuln_type = self.get_vuln_type(func_name)
                    for vuln_info in vuln_infos:
                        call_info = self.backward_analyzer.code_manager.collect_report_codes(vuln_info)
                        if self.is_valid_source(call_info):
                            self.reporter.output_report(call_info, vuln_type, func_name)
                            detected_vul_num += 1
                    self.check_memory()
                    self.log_manager.log_cost("static_analysis_time", time.time() - t1)
                except:
                    try:
                        self.backward_analyzer.joern_server.restart_joern_service()
                    except:
                        pass
            return detected_vul_num
        except:
            return detected_vul_num

def invoke_detector(input_path: str, output_path: str):
    if not input_path or not output_path:
        print("输入路径无效! 请提供`输入信息的JSON文件地址` `输出信息的JSON文件地址`")
        return

    if input_path.find(".json") == -1 or output_path.find(".json") == -1:
        print("输入路径无效! 请输入有效的JSON地址")
        return

    if not os.path.exists(input_path):
        print("输入路径对应JSON文件不存在!")
        return
    
    input_data = {}
    with open(input_path, "r", encoding = "utf-8") as f:
        input_data = json.load(f)
    
    repo_path = input_data.get("path", None)
    if not repo_path or not os.path.exists(repo_path):
        print("待分析组件仓库不存在,请检查JSON文件参数!")
        return

    detected_vul_num = 0
    test = None
    try:
        t1 = time.time()
        test = VulnDetector(repo_path)
        test.log_manager.log_cost("construct_cpg_time", time.time() - t1)
        detected_vul_num = test.process_sink_files()
        test.check_memory()
        test.joern_server.close_cpg()
        test.check_memory()
        test.log_manager.log_cost("Init memory usage", f"{test.init_memory/(1024**3):.6f} GB")
        test.log_manager.log_cost("Peak memory usage", f"{test.peak_memory/(1024**3):.6f} GB")
        test.log_manager.log_info(f"Detect {detected_vul_num} Vulneriablies!", False, 0, True)
        test = None
    except:
        pass

    # 输出分析结果
    print(f"Detect {detected_vul_num} Vulneriablies!")
    with open(output_path, "w", encoding = "utf-8") as f:
        json.dump({"detected_vul_num": detected_vul_num}, f, ensure_ascii = False, indent = 4)

if __name__ == "__main__":
    # invoke_detector(input_path = "/home/devdata/tencent/AutoPoC/test/input.json", output_path = "/home/devdata/tencent/AutoPoC/output.json")
    repo_paths = [
        "/home/devdata/PoCForge/test"
    ]

    for repo_path in repo_paths:
        try:
            repo_name = repo_path.split(os.sep)[-1]
            print(f'正在处理: {repo_name}')
            t1 = time.time()
            test = VulnDetector(repo_path)
            test.log_manager.log_cost("construct_cpg_time", time.time() - t1)
            detected_vul_num = test.process_sink_files()
            test.check_memory()
            test.joern_server.close_cpg()
            test.check_memory()
            test.log_manager.log_cost("Init memory usage", f"{test.init_memory/(1024**3):.6f} GB")
            test.log_manager.log_cost("Peak memory usage", f"{test.peak_memory/(1024**3):.6f} GB")
            test.log_manager.log_info(f"当前已找到 {detected_vul_num} 个漏洞", False, 0, True)
            test = None

            # 输出分析结果
            output_data = {}
            output_path = "/home/devdata/tencent/AutoPoC/config.json"
            if os.path.exits(output_path):
                with open(output_path, "r", encoding = "utf-8") as f:
                    output_data = json.load(f)

            if repo_name not in output_data.keys():
                output_data[repo_name] = {}
            output_data[repo_name]["detected_vul_num"] = detected_vul_num
            output_data[repo_name]["time_spend"] = int(time.time() - t1) / 60

            with open(output_path, "w", encoding = "utf-8") as f:
                json.dump(output_data, f, ensure_ascii = False, indent = 4)
        except Exception as e:
            # raise e
            pass
#     # test.process_source_files()