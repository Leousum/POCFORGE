import os
import re
import time
import json
import requests
import subprocess
from git import Repo

import config
from log_manager import LogManager

class RepositoryHandler():
    def __init__(self, log_manager: LogManager) -> None:
        self.log_manager = log_manager
        self.repo_root = config.REPO_ROOT
        self.github_token = config.GITHUB_TOKEN
        self.info_root = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "data", "repo_info")
        if not os.path.exists(self.info_root):
            os.makedirs(self.info_root, mode = 777)

    def _connect_github(self, url, github_token):
        headers = {
            'Authorization': 'token ' + github_token,
            "Accept-Language": 'q=0.9,en;q=0.8',
            'Accept': 'application/vnd.github.cloak-preview+json'
        }
        session = requests.session()
        session.keep_alive = False
        try:
            response = requests.get(url, headers=headers, timeout=(18, 72))
            if response.status_code != 200:
                self.log_manager.log_info("Github token may have expired, please replace it!", False, 1)
                return None
            else:
                return response
        except Exception as e:
            self.log_manager.log_info("Github token may have expired, please replace it!", False, 1)
            return None

    def _extract_tag_num(self, tag):
        if tag.lower().startswith("cpe:2.3:") and len(tag.lower().split(":")) >= 6:
            tag = tag.lower().split(":")[5]
        try:
            num = re.search(r"(\d+\.?)+", str(tag).replace('_', '.').replace('-', '.')).group().strip(".")
            return str(num)
        except:
            return None

    def _check_format(self, tag):
        tag = tag.lower()
        if not (re.search("a(\d+)", tag) or re.search("b(\d+)", tag) or
                re.search("rc(\d+)", tag) or re.search("snapshot", tag) or
                re.search("alpha", tag) or re.search("beta", tag)):
            return True
        else:
            return False

    def _collect_repo_info(self, git_link, info_root, github_token):
        '''
        Collect the component repository tag information and save it in json format in the info_root directory
        '''
        vendor = git_link.split('/')[-2].lower()
        product = git_link.split('/')[-1].lower()
        repo_info = dict()
        repo_info["git_link"] = git_link
        repo_info["vendor"] = vendor
        repo_info["product"] = product
        repo_info["language"] = list()
        repo_info["tags"] = list()
        repo_info["num2tag"] = dict()
        repo_info["update_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        info_path = os.path.join(info_root, vendor + "_" + product + ".json")
        github_api_link = git_link.replace("github.com", "api.github.com/repos")
        response = self._connect_github(github_api_link, github_token)
        if response:
            response_content = json.loads(response.text)
            try:
                if "languages_url" in response_content.keys():
                    language_response = self._connect_github(response_content["languages_url"], github_token)
                    language_content = json.loads(language_response.text)
                    repo_info["language"] = list(language_content.keys())
                elif "language" in response_content.keys():
                    repo_info["language"] = [response_content["language"]]
            except:
                pass
            tags_base_url = response_content["tags_url"]
            tags_base_url = tags_base_url[:tags_base_url.find("tags") + len("tags")]
            page_num = 1
            tags_url = tags_base_url + "?per_page=100&page=" + str(page_num)
            tags_response = self._connect_github(tags_url, github_token)
            while tags_response:
                tags_content = json.loads(tags_response.text)
                self.log_manager.log_info("Processing tags url: " + tags_url, False, 1)
                if tags_content == []:
                    break
                for tag_dict in tags_content:
                    tag = tag_dict["name"]
                    repo_info["tags"].append(tag)
                    # Construct the mapping between tag number and tag
                    tag_num = self._extract_tag_num(tag)
                    if tag_num:
                        if tag_num not in repo_info["num2tag"].keys():
                            repo_info["num2tag"][tag_num] = tag
                        if self._check_format(tag):
                            repo_info["num2tag"][tag_num] = tag
                page_num += 1
                tags_url = tags_base_url + "?per_page=100&page=" + str(page_num)
                tags_response = self._connect_github(tags_url, github_token)
        with open(info_path, "w", encoding = "utf-8") as f:
            json.dump(repo_info, f, ensure_ascii = False, indent = 4)

    def _download_repo(self, git_link):
        '''
        Download the component repository to the specified directory
        '''
        success = False
        repo_path = None
        if not os.path.exists(self.repo_root):
            os.mkdir(self.repo_root, mode = 0o777)
        if git_link.endswith('.git'):
            git_link = git_link[:-4]
        if git_link.find("/github.com/") != -1:
            try:
                vendor = git_link.split('/')[-2].lower()
                product = git_link.split('/')[-1].lower()
                repo_path = os.path.join(self.repo_root, vendor + "_" + product)
                if not os.path.exists(repo_path):
                    subprocess.call(['git','clone', git_link + ".git", repo_path])
                success = True
            except:
                success = False
        if success:
            self.log_manager.log_info(f'组件仓库下载完成!', False, 1)
        else:
            self.log_manager.log_info(f'组件仓库下载失败!', False, 1)
        if repo_path is not None and not os.path.exists(repo_path):
            repo_path = None
        return repo_path, success

    def checkout_tag(self, git_link, versions):
        '''
        Switches the repository to the specified tag
        '''
        self.log_manager.log_info(f'收集组件仓库信息', True, 0)
        self.log_manager.log_result("git_link", git_link)
        repo_path, download_success = self._download_repo(git_link)
        checkout_success = False
        checkout_tag = None
        if download_success:
            vendor = git_link.split('/')[-2].lower()
            product = git_link.split('/')[-1].lower()
            info_path = os.path.join(self.info_root, vendor + "_" + product + ".json")
            if not os.path.exists(info_path):
                self._collect_repo_info(git_link, self.info_root, self.github_token)
            tag_nums = list()
            for version in versions:
                tag_num = self._extract_tag_num(version)
                if tag_num:
                    tag_nums.append(tag_num)
            tag_nums = sorted(list(set(tag_nums)), key = lambda x:tuple(int(v) for v in x.split(".")), reverse = True)
            repo_info = dict()
            if os.path.exists(info_path):
                with open(info_path, "r", encoding = "utf-8") as f:
                    repo_info = json.load(f)
            for tag_num in tag_nums:
                if "num2tag" in repo_info.keys():
                    if tag_num in repo_info["num2tag"].keys():
                        tag = repo_info["num2tag"][tag_num]
                        try:
                            repo = Repo(repo_path)
                            repo.git.checkout(tag, force = True)
                            checkout_success = True
                            checkout_tag = tag
                            break
                        except:
                            checkout_success = False
        if checkout_success:
            self.log_manager.log_info(f'组件仓库已被切换至: {checkout_tag}', False, 1)
            self.log_manager.log_result("tag", checkout_tag)
        else:
            self.log_manager.log_info(f'组件仓库切换版本失败!', False, 1)
        return repo_path, checkout_tag, checkout_success

    def _collect_language(self, git_link, github_token):
        '''
        Collect the component repository language
        '''
        language = ""
        github_api_link = git_link.replace("github.com", "api.github.com/repos")
        response = self._connect_github(github_api_link, github_token)
        if response:
            response_content = json.loads(response.text)
            try:
                if "languages_url" in response_content.keys():
                    language_response = self._connect_github(response_content["languages_url"], github_token)
                    language_content = json.loads(language_response.text)
                    if language_content:
                        if language_content.keys():
                            language = list(language_content.keys())
                if language == "" or language == [] or language == [None]:
                    if "language" in response_content.keys():
                        language = [response_content["language"]]
            except:
                pass
        return language