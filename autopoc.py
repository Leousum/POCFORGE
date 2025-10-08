# -*- encoding: utf-8 -*-
'''
@File     :   autopoc.py
@Function :   Automatically construct the poc that triggers the vulnerability based on the vulnerability description and source code
@Usage :   python3 autopoc.py
'''
import os
import json
import config
import shutil
import traceback
import subprocess

from LLM.model_manager import ModelManager
from utils.log_manager import LogManager
from utils.process_repo import RepositoryHandler
from static_analysis.inferencer import InferManager
from joern_manager.joern import JoernServer

class PocGenerator():
    def __init__(self) -> None:
        self.input_root = config.INPUT_ROOT
    
    def _config_load(self, config_file_path: str):
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config = json.load(config_file)
            return config
    
    def _clear_files(self, repo_path):
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
    
    def _get_manual_poc(self, source_id):
        poc_path = os.path.join(self.input_root, source_id + ".json")
        if os.path.exists(poc_path):
            vuln_data = dict()
            with open(poc_path, "r", encoding = "utf-8") as f:
                vuln_data = json.load(f)
            if "manual_poc" in vuln_data.keys():
                return vuln_data["manual_poc"]
        return []
    
    def make_url(self, manual_poc):
        content = f"{manual_poc['host']}/{manual_poc['path']}?"
        for k in manual_poc["data"].keys():
            content += f"{k}={manual_poc['data'][k]}"
        return content

    def hava_info(self, gpt_infos: list):
        for item in gpt_infos:
            url_flag = False
            para_flag = False
            if "Target" in item.keys():
                if item["Target"]:
                    url_flag = True
            if "Parameters" in item.keys():
                for para in item["Parameters"]:
                    if "name" in para.keys():
                        if para["name"]:
                            para_flag = True
            if url_flag or para_flag:
                return True
        return False
    
    def generate_poc(self, source_id: str, vuln_type: str, description: str, git_link: str, affected_version: list):
        '''
        Generate poc based on vulnerability information
        '''
        log_manager = LogManager(source_id, vuln_type)
        # Extract information from description
        model_manager = ModelManager(log_manager)
        gpt_infos = model_manager.info_extract(vuln_type, description)
        # Download repository and switch tag
        repo_handler = RepositoryHandler(log_manager)
        repo_path, checkout_tag, checkout_success = repo_handler.checkout_tag(git_link, affected_version)
        info_flag = self.hava_info(gpt_infos)
        if not checkout_success or not info_flag:
            return None, None
        # Use static analysis to infer information
        automated_poc = list()
        if repo_path:
            log_manager.log_result("repo_path", repo_path)
            joern_server = JoernServer(config.JOERN_SERVER_POINT, repo_path, log_manager) # checkout_tag
            infer_manager = InferManager(model_manager, joern_server, log_manager)
            automated_poc = infer_manager.code_analysis(vuln_type, repo_path, gpt_infos)
        else:
            log_manager.log_result("repo_path", None)
        # self._clear_files(repo_path)
        # Verify that the poc is correct
        manual_poc = self._get_manual_poc(source_id)
        log_manager.log_result("manual_poc", manual_poc)
        return automated_poc

if __name__ == "__main__":
    test = PocGenerator()
    for parent, dirnames, filenames in os.walk(test.input_root):
        for filename in filenames:
            vuln_path = os.path.join(parent, filename) # The path of the JSON file to be analyzed for vulnerability
            vuln_data = dict()
            with open(vuln_path, "r", encoding = "utf-8") as f:
                vuln_data = json.load(f)
            try:
                automated_poc = test.generate_poc(vuln_data["source_id"], vuln_data["vuln_type"], vuln_data["description"], vuln_data["git_links"][0], vuln_data["affected_version"])
            except Exception as e:
                print(f"处理{vuln_data['source_id']}时发生了错误!")
                command = ["fuser", "-k", "8989/tcp"]
                subprocess.Popen(command, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL, start_new_session = True)
                logmanager = LogManager(vuln_data["source_id"], vuln_data["vuln_type"])
                manual_poc = test._get_manual_poc(vuln_data["source_id"])
                logmanager.log_result("manual_poc", manual_poc)
                logmanager.log_result(f"verificate_poc", {"answer": "", "failure_reason": "", "new_parameters": 0, "parameter_error": False})
                logmanager.log_result("error", str(e) + ":" + str(traceback.format_exc()))
                logmanager = None