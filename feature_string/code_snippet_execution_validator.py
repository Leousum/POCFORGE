import os
import re
import json
import subprocess
import xml.etree.ElementTree as ET

from crawl_php_api import crawl_php_doc
import json

class ExecuteFileType(enumerate):
    PHP = "php"
    JAVA = "java"
    PYTHON = "python"

class VulnType(enumerate):
    XSS = "xss"
    SQLI = "sqli"
    CSRF = "csrf"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"

class CodeExecutor:
    def __init__(self):
        self.payload_dir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "CommonPayload")
        self.feature_str_dir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "FeatureString")
        self.built_in_api_dir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "Built_In_APIs", "Origin")
        self.experiment_dir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "experiment")
        self.user_defined_functions_dir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "UserDefinedFunctions")
        self.create_dirs()
        self.vuln_types = ["xss", "sqli", "csrf", "directory_traversal", "command_injection"]
        self.separators = [" ", "\"", "\'", "(", ")", "{", "}", "[", "]", "=", ";", ":", ",", ".", "?", "!", "@", "#", "$", "%", "^", "&", "*", "-", "_", "+", "~", "`", "|", "\\", "/"]
        self.count_limit = 5 # 统计次数阈值
        self.TAINTED = "$taint_data" # 污点字符串
    
    def create_dirs(self):
        """
        检查所需目录是否存在，如果不存在则创建
        """
        for dir_path in [self.payload_dir, self.feature_str_dir, self.experiment_dir, self.user_defined_functions_dir]:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, mode = 0o777)

    def split_string(self, text):
        # 转义所有特殊字符并构建正则模式
        pattern = r"[" + re.escape("".join(self.separators)) + r"]+"
        # 分割并过滤空字符串
        return [part for part in re.split(pattern, text) if part]

    def split_payloads(self):
        """
        拆分所有 payload 字符串，并将结果存储到对应的 JSON 文件中。
        """
        # 初始化一个字典，用于存储每类漏洞划分结果的出现次数
        vuln_feature_counts = {}
        for vuln_type in self.vuln_types:
            for vuln_type in self.vuln_types:
                if vuln_type not in vuln_feature_counts:
                    vuln_feature_counts[vuln_type] = {}

                # 构建当前漏洞类型的 payload 文件路径
                payload_file_path = os.path.join(self.payload_dir, f"{vuln_type}_payloads.json")
                if os.path.exists(payload_file_path):
                    try:
                        # 读取 payload 文件
                        with open(payload_file_path, 'r', encoding='utf-8') as f:
                            payloads = json.load(f)

                        # 初始化当前漏洞类型的统计字典
                        features = []
                        feature_counts = {}
                        for payload in payloads:
                            # 按照 self.separators 进行划分
                            features.extend(self.split_string(payload))
                        # 统计每个特征字符串的出现次数
                        for feature in features:
                            # 过滤纯数字或长度小于2的特征字符串
                            if feature.isdigit() or len(feature) < 2:
                                continue
                            if feature in feature_counts:
                                feature_counts[feature] += 1
                            else:
                                feature_counts[feature] = 1

                        # 将当前漏洞类型的统计结果存入总字典
                        for feature, count in feature_counts.items():
                            if feature in vuln_feature_counts[vuln_type]:
                                vuln_feature_counts[vuln_type][feature] += count
                            else:
                                vuln_feature_counts[vuln_type][feature] = count
                    except Exception as e:
                        print(f"读取 {payload_file_path} 时出错: {e}")
                else:
                    print(f"{payload_file_path} 文件不存在")

        # 遍历每个漏洞类型，将统计结果写入对应的 JSON 文件
        all_num = 0
        sorted_vuln_feature_counts = {}
        for vuln_type, feature_counts in vuln_feature_counts.items():
            # 构建当前漏洞类型的输出文件路径
            output_file_path = os.path.join(self.feature_str_dir, f"{vuln_type}_feature_strings.json")
            
            # 统计feature_counts中出现次数大于5的特征字符串
            filtered_feature_counts = {feature: count for feature, count in feature_counts.items() if count > self.count_limit}

            # 对过滤后的特征字符串按照出现次数从大到小排序
            sorted_feature_counts = sorted(filtered_feature_counts.items(), key=lambda x: x[1], reverse=True)
            for feature, count in sorted_feature_counts:
                if vuln_type not in sorted_vuln_feature_counts:
                    sorted_vuln_feature_counts[vuln_type] = {}
                    sorted_vuln_feature_counts[vuln_type][feature] = count
                else:
                    sorted_vuln_feature_counts[vuln_type][feature] = count

            # 提取排序后的特征字符串
            sorted_features = [feature for feature, count in sorted_feature_counts]
            # 将排序后的特征字符串写入 JSON 文件
            with open(output_file_path, 'w', encoding = 'utf-8') as f:
                json.dump(sorted_features, f, ensure_ascii = False, indent = 4)
            # 输出当前漏洞类型的统计结果
            all_num += len(sorted_features)
            print(f"{vuln_type}漏洞的特征字符串数量为: {len(sorted_features)}")
        
        # 将整体排序后的特征字符串写入 JSON 文件
        output_file_path = os.path.join(self.feature_str_dir, f"feature_strings.json")
        with open(output_file_path, 'w', encoding = 'utf-8') as f:
            json.dump(sorted_vuln_feature_counts, f, ensure_ascii = False, indent = 4)
        # 输出总体的统计结果
        print(f"特征字符串总数: {all_num}")

    def get_feature_strings(self, vuln_type: VulnType):
        """
        获取指定漏洞类型的特征字符串
        """
        feature_strings = []
        # 构建当前漏洞类型的输出文件路径
        output_file_path = os.path.join(self.feature_str_dir, f"{vuln_type}_feature_strings.json")
        if os.path.exists(output_file_path):
            try:
                # 读取 JSON 文件
                with open(output_file_path, 'r', encoding='utf-8') as f:
                    feature_strings = json.load(f)
            except Exception as e:
                print(f"读取 {output_file_path} 时出错: {e}")
        # 将连接符号加入到特征字符串中
        for char in self.separators:
            if char not in feature_strings and char != "'":
                feature_strings.append(char)
        # 进行转义
        feature_strings = json.dumps(str(feature_strings))[1:-1]
        return feature_strings

    def search_api(self, method_name):
        """
        从self.built_in_api_dir中搜索与method_name匹配的API
        """
        def normalize_code(code):
            """
            标准化代码
            """
            if not isinstance(code, str):
                try:
                    code = code.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        code = code.decode('gbk', errors='ignore')
                    except:
                        pass
            return code

        def parse_example_code(method_xml_dir, method_name, param_index, param_name):
            """
            解析示例代码,获取参数的示例值
            """
            example_code = ""
            example_code_path = os.path.join(method_xml_dir, "Code#1.php")
            arg_variable_name = None # 形参对应的实参变量名
            arg_variable_def_value = None # 实参变量的值

            if os.path.exists(example_code_path):
                codess = []
                with open(example_code_path, 'r', encoding='utf-8') as f:
                    codess = f.readlines()
                
                # 遍历所有代码,找到函数访问语句
                for code in codess:
                    code = normalize_code(code)

                    if arg_variable_name is not None:
                        break

                    if code.find(method_name) != -1 and code.find("(") != -1 and code.find(")") != -1:
                        # 提取函数访问代码 例如从$output = array_slice($input, 2);中提取出array_slice($input, 2)
                        method_call_statement = code[code.find(method_name):code.rfind(")") + 1]
                        method_call_statement = method_call_statement[:method_call_statement.find(")") + 1] # 去除无用的反括号
                        # 提取参数
                        arg_list_str = method_call_statement[method_call_statement.find("(") + 1:method_call_statement.find(")")]
                        arg_list = []
                        if arg_list_str.find(",")!= -1:
                            arg_list = arg_list_str.split(",")
                        elif arg_list_str.find(", ")!= -1:
                            arg_list = arg_list_str.split(", ")
                        else:
                            arg_list.append(arg_list_str)
                        # 依次比对参数,观察是否是所需的那个参数
                        for arg_index in range(len(arg_list)):
                            arg = arg_list[arg_index]
                            
                            try:
                                if arg.find("=") != -1 and param_name and arg.find(param_name) != -1:
                                    # 处理 param = value 的形参赋值
                                    arg_variable_name = arg[:arg.find("=")].strip()
                                elif str(int(arg_index) + 1) == param_index:
                                    # 处理 arg1, arg2, ... 的形参赋值
                                    arg_variable_name = arg.strip()
                            except:
                                pass
                
                # 再次遍历所有代码,找到实参变量定义
                if arg_variable_name is not None:
                    if arg_variable_name.find("$") == -1:
                        arg_variable_def_value = arg_variable_name
                    else:
                        arg_variable_defs = [arg_variable_name + " =", arg_variable_name + "="]
                        for code in codess:
                            code = normalize_code(code)
                            if code.find(arg_variable_defs[0]) != -1 or code.find(arg_variable_defs[1]) != -1:
                                arg_variable_def_str = arg_variable_defs[0] if code.find(arg_variable_defs[0]) != -1 else arg_variable_defs[1]
                                arg_variable_def_value = code[code.find(arg_variable_def_str) + len(arg_variable_def_str):code.rfind(";")]
                                break
            
            # 返回实参的定义语句
            if arg_variable_def_value:
                arg_variable_def_value = arg_variable_def_value.strip()
                if arg_variable_def_value.startswith("'") and arg_variable_def_value.endswith("'"):
                    arg_variable_def_value = f'"{arg_variable_def_value[1:-1]}"'
            return arg_variable_def_value

        def parse_xml_file(method_xml_dir):
            """
            解析XML文件并返回参数信息
            """
            params_info = []
            method_xml_path = os.path.join(method_xml_dir, "Rule.xml")
            if os.path.exists(method_xml_path):
                # 解析XML文件
                tree = ET.parse(method_xml_path)
                root = tree.getroot()
                
                # 查找所有的 Parameter 节点
                parameters = root.findall('.//Parameters/Parameter')
                for param in parameters:
                    # 提取每个参数的信息
                    param_type = param.find('ParamType').text.strip() if param.find('ParamType') is not None else None
                    param_index = param.find('ParamIndex').text.strip() if param.find('ParamIndex')  is not None else None
                    param_name = param.find('ParamName').text.strip() if param.find('ParamName')  is not None else None
                    param_default = param.find('ParamDefault').text.strip() if param.find('ParamDefault')  is not None else None
                    param_example = parse_example_code(method_xml_dir, method_name, param_index, param_name)
                    # 将参数信息存储为字典
                    param_dict = {
                        "ParamType": param_type,
                        "ParamIndex": param_index,
                        "ParamName": param_name,
                        "ParamDefault": param_default,
                        "ParamExample": param_example
                    }
                    # 将参数信息字典添加到列表中
                    params_info.append(param_dict)
            return params_info

        # 初始化参数信息列表
        params_info = []
        method_xml_dir = None
        method_xml_path = None
        # 检查是否存在以此方法名称命名的文件夹
        if os.path.exists(os.path.join(self.built_in_api_dir, method_name)):
            method_xml_dir = os.path.join(self.built_in_api_dir, method_name)
            params_info = parse_xml_file(method_xml_dir)
        else:
            # 遍历self.built_in_api_dir中的所有XML文件
            for filename in os.listdir(self.built_in_api_dir):
                if filename.lower().endswith(method_name):
                    method_xml_dir = os.path.join(self.built_in_api_dir, filename)
                    params_info = parse_xml_file(method_xml_dir)
        if method_name == "doubleval":
            params_info = [
                {
                    "ParamType": "mixed",
                    "ParamIndex": "1",
                    "ParamName": "$value",
                    "ParamDefault": "None",
                    "ParamExample": "\"122.34343The\""
                }
            ]
        return params_info, method_xml_dir, os.path.join(method_xml_dir, "Rule.xml")

    def is_num(self, str_index: str):
        try:
            index = int(str_index)
            return True
        except:
            return False

    def get_function_name(self, signature: str):
        return signature[signature.find(" ") + 1:signature.find("(")]

    def get_selected_functions_info(self):
        """
        获取选定的函数的参数信息
        """
        # 测试100个PHP内置函数是否具有清理污点数据的能力
        origin_built_in_function_names = []
        with open(os.path.join(self.experiment_dir, "built_in_function_names.json"), "r", encoding = "utf-8") as file:
             origin_built_in_function_names = json.load(file)
        built_in_function_names = [func_name for func_name in origin_built_in_function_names if not func_name.startswith("---")]
        has_info = []
        # 获取内置函数信息
        sanitizer_info = {}
        candidate_sanitizers = []
        for sanitizer in built_in_function_names:
            sanitizer_info[sanitizer] = {}
            params_info, method_xml_dir, method_xml_path = executor.search_api(sanitizer)
            if params_info:
                has_info.append(sanitizer)
            sanitizer_info[sanitizer] = params_info
        # TODO:此处暂时注释掉
        # origin_built_in_function_names = [func_name for func_name in origin_built_in_function_names if func_name.startswith("---") or func_name in has_info]
        # with open(os.path.join(self.experiment_dir, "built_in_function_names.json"), "w", encoding = "utf-8") as file:
        #     json.dump(origin_built_in_function_names, file, ensure_ascii = False, indent = 4)
        func_arg_map_path = os.path.join(self.experiment_dir, "built_in_functions_arg_map.json")
        with open(func_arg_map_path, "w", encoding = "utf-8") as file:
            json.dump(sanitizer_info, file, ensure_ascii = False, indent = 4)
        return sanitizer_info

# ============================================================================ 核心功能 ============================================================================
    def is_global_string(self, input_string: str):
        """
        检查输入字符串是否是一个全局变量 例如"ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401"
        """
        if input_string:
            # 判断输入字符串中的字母是否全为大写
            letters_only = ''.join(filter(str.isalpha, input_string))
            if letters_only.isupper():
                return True
        return False
    
    def maybe_taint_data(self, param_type: str, param_default: str, need_array: bool = False):
        """
        判断是否可能是污点数据
        """
        if param_type is None or param_default is None:
            return False
        # (1) 认为有默认数据的一般不是注入点
        if param_default.strip != "None":
            return False
        # (2) 认为类型可以为string、mixed的可能是注入点
        if param_type.find("string") != -1 or param_type.find("mixed") != -1:
            return True
        # (3) 认为array也可以是污点输入
        if need_array and param_type.find("array") != -1:
            return True
        return False

    def construct_default_value(self, var_type: str):
        """
        构造默认值
        """
        if var_type == "int":
            return 1
        elif var_type == "string":
            return "\"test\""
        elif var_type == "array":
            return "[\"apple\", \"banana\", \"cherry\"]"
        else:
            return null

    def construct_php_code(self, base_code, call_code, root_path, func_name: str = None, is_user_defined: bool = False):
        base_statement = base_code + "\n" if base_code else ""
        xss_feature_strings = self.get_feature_strings(VulnType.XSS)
        sqli_feature_strings = self.get_feature_strings(VulnType.SQLI)
        csrf_feature_strings = self.get_feature_strings(VulnType.CSRF)
        directory_traversal_feature_strings = self.get_feature_strings(VulnType.DIRECTORY_TRAVERSAL)
        command_injection_feature_strings = self.get_feature_strings(VulnType.COMMAND_INJECTION)

        user_defined_function_str = ""
        if is_user_defined:
            # 获取用户自定义函数的所有代码
            user_defined_function_codes = []
            user_defined_function_path = os.path.join(self.user_defined_functions_dir, func_name + ".php")
            if os.path.exists(user_defined_function_path):
                with open(user_defined_function_path, "r", encoding = "utf-8") as file:
                    user_defined_function_codes = file.readlines()
            if user_defined_function_codes:
                # 排除首行"<?php"
                user_defined_function_codes = user_defined_function_codes[1:]
            user_defined_function_str = "".join(user_defined_function_codes) + "\n" if user_defined_function_codes else ""

        php_code ="""<?php\n""" + user_defined_function_str + """
function testSanitizer($taint_data) {
    try {
        $original_data = $taint_data;\n""" + \
        base_statement + \
        """        $cleaned_data = """ + call_code + """;
        if ($original_data === $cleaned_data) {
            return 0;
        } else {
            return 1;
        }
    } catch (Exception $e) {
        return -1;
    }
}

// Test XSS vulnerability feature strings
$xss_tp = 0;
$xss_fp = 0;
$xss_error = 0;
try {
    $xss_feature_strings = """ + xss_feature_strings + """;
    foreach ($xss_feature_strings as $feature_string) {
        $res = testSanitizer($feature_string);
        if ($res === 1) {
            $xss_tp += 1;
        } elseif ($res === 0) {
            $xss_fp += 1; 
        } else {
            $xss_error += 1;
        }
    }
} catch (Exception $e) {
    ;
}

// Test SQLi vulnerability feature strings
$sqli_tp = 0;
$sqli_fp = 0;
$sqli_error = 0;
try {
    $sqli_feature_strings = """ + sqli_feature_strings + """;
    foreach ($sqli_feature_strings as $feature_string) {
        $res = testSanitizer($feature_string);
        if ($res === 1) {
            $sqli_tp += 1;
        } elseif ($res === 0) {
            $sqli_fp += 1; 
        } else {
            $sqli_error += 1;
        }
    }
} catch (Exception $e) {
    ;
}

// Test CSRF vulnerability feature strings
$csrf_tp = 0;
$csrf_fp = 0;
$csrf_error = 0;
try {
    $csrf_feature_strings = """ + csrf_feature_strings + """;
    foreach ($csrf_feature_strings as $feature_string) {
        $res = testSanitizer($feature_string);
        if ($res === 1) {
            $csrf_tp += 1;
        } elseif ($res === 0) {
            $csrf_fp += 1; 
        } else {
            $csrf_error += 1;
        }
    }
} catch (Exception $e) {
    ;
}

// Test Directory Traversal vulnerability feature strings
$directory_traversal_tp = 0;
$directory_traversal_fp = 0;
$directory_traversal_error = 0;
try {
    $directory_traversal_feature_strings = """ + directory_traversal_feature_strings + """;
    foreach ($directory_traversal_feature_strings as $feature_string) {
        $res = testSanitizer($feature_string);
        if ($res === 1) {
            $directory_traversal_tp += 1;
        } elseif ($res === 0) {
            $directory_traversal_fp += 1; 
        } else {
            $directory_traversal_error += 1;
        }
    }
} catch (Exception $e) {
    ;
}

// Test Command Injection vulnerability feature strings
$command_injection_tp = 0;
$command_injection_fp = 0;
$command_injection_error = 0;
try {
    $command_injection_feature_strings = """ + command_injection_feature_strings + """;
    foreach ($command_injection_feature_strings as $feature_string) {
        $res = testSanitizer($feature_string);
        if ($res === 1) {
            $command_injection_tp += 1;
        } elseif ($res === 0) {
            $command_injection_fp += 1; 
        } else {
            $command_injection_error += 1;
        }
    }
} catch (Exception $e) {
    ;
}

// Output All Results
$data = array(
    "xss_tp" => $xss_tp,
    "xss_fp" => $xss_fp,
    "xss_error" => $xss_error,
    "sqli_tp" => $sqli_tp,
    "sqli_fp" => $sqli_fp,
    "sqli_error" => $sqli_error,
    "csrf_tp" => $csrf_tp,
    "csrf_fp" => $csrf_fp,
    "csrf_error" => $csrf_error,
    "directory_traversal_tp" => $directory_traversal_tp,
    "directory_traversal_fp" => $directory_traversal_fp,
    "directory_traversal_error" => $directory_traversal_error,
    "command_injection_tp" => $command_injection_tp,
    "command_injection_fp" => $command_injection_fp,
    "command_injection_error" => $command_injection_error
);
echo json_encode($data);
?>
"""
        code_path = os.path.join(root_path, f"built_in.php")
        if is_user_defined:
            code_path = os.path.join(root_path, f"user_defined.php")
        with open(code_path, "w") as file:
            file.write(php_code)
        return "php", code_path

    def construct_base_call_statement(self, func_name: str, arguments_map: list):
        """
        构造函数调用者语句和函数调用者语句
        """
        def generate_statement(arg_vule):
            if arg_value == "\"":
                return "\'\"\', "
            elif isinstance(arg_value, int):
                return f"{arg_value}, "
            elif arg_value.startswith("[") and arg_value.endswith("]"):
                return f"{arg_value}, "
            elif arg_value.startswith("\"") and arg_value.endswith("\""):
                return f"{arg_value}, "
            elif arg_value.startswith("\"") or arg_value.endswith("\""):
                return f"'{arg_value}', "
            else:
                return f"{arg_value}, "

        base_statement = None
        method_call_statement = None
        for arg_map in arguments_map:
            if arg_map["argIndex"] == "0":
                if arg_map["argValue"] is not None:
                    base_statement = f"$base = {generate_statement(arg_map['argValue'])};"
            else:
                if method_call_statement is None:
                    method_call_statement = f"{func_name}("

                if arg_map["argType"] and arg_map["argType"] != "None":
                    # 获取参数值
                    arg_value = arg_map["argValue"]
                    if arg_value is None:
                        arg_value = self.construct_default_value(arg_map["argType"])
                    # 构造函数调用语句
                    if arg_value is not None:
                        if arg_value == "null":
                            break
                        else:
                            method_call_statement += generate_statement(arg_value)
        if method_call_statement is not None:
            method_call_statement = method_call_statement.strip().strip(",") + ")"
        if base_statement is not None and method_call_statement is not None:
            method_call_statement = f"$base.{method_call_statement}"
        return base_statement, method_call_statement

    def output_result(self, method_name, result: dict):
        """
        输出结果
        """
        print(method_name, end = "\t")

        if not isinstance(result, dict):
            result = {}
        # 获取各类漏洞被清理的特征字符串数量
        xss_tp = result.get("xss_tp", 0)
        sqli_tp = result.get("sqli_tp", 0)
        csrf_tp = result.get("csrf_tp", 0)
        directory_traversal_tp = result.get("directory_traversal_tp", 0)
        command_injection_tp = result.get("command_injection_tp", 0)
        
        # 判断是否验证成功
        if xss_tp > 0 or sqli_tp > 0 or csrf_tp > 0 or directory_traversal_tp > 0 or command_injection_tp > 0:
            print("是", end = "\t")
        else:
            print("否", end = "\t")
        
        # 获取可以清理的特征字符串数量
        print(f"{xss_tp + sqli_tp + csrf_tp + directory_traversal_tp + command_injection_tp}", end = "\t")

        # 获取可以清理的漏洞类型
        vuln_types = ""
        if xss_tp > 0:
            vuln_types += "XSS "
        if sqli_tp > 0:
            vuln_types += "SQLI "
        if csrf_tp > 0:
            vuln_types += "CSRF "
        if directory_traversal_tp > 0:
            vuln_types += "DirectoryTraversal "
        if command_injection_tp > 0:
            vuln_types += "CommandInjection "
        vuln_types = vuln_types.strip()
        if vuln_types:
            print(vuln_types)
        else:
            print("None")

    def test_sanitizer_by_feature_strings(self, file_type: ExecuteFileType, func_name: str, arguments_map: list, is_user_defined: bool = False):
        """
        测试方法能否过滤特征字符串, 即是否具有污点清理能力
        """
        error_flag = True
        result = dict()

        # (1) 构造语句
        base_statement, method_call_statement = self.construct_base_call_statement(func_name, arguments_map)
        
        # (2) 构造源码
        root_path = os.path.join(self.experiment_dir, func_name)
        if not os.path.exists(root_path):
            os.makedirs(root_path, mode = 0o777)
        interpreter = None
        code_path = None
        if file_type == ExecuteFileType.PHP:
            interpreter, code_path = self.construct_php_code(base_statement, method_call_statement, root_path, func_name, is_user_defined)
        
        # 执行语句
        if code_path is not None and interpreter is not None:
            run_function = subprocess.run([interpreter, code_path], capture_output = True, text = True)
            # os.remove(code_path)
            if run_function.returncode == 0:
                error_flag = False
                result = json.loads(run_function.stdout)
        return error_flag, result

    def test_all_built_in_apis(self):
        """
        测试所有PHP内置函数的污点清理能力
        """
        def get_taint_index(arg_map: dict):
            # 选定污点数据的索引
            candidate_taint_data_indexs = [] # 候选的污点数据索引
            # 优先选择字符串类型的参数
            for param_dict in arg_map:
                if self.maybe_taint_data(param_dict["ParamType"], param_dict["ParamDefault"], need_array = False):
                    candidate_taint_data_indexs.append(param_dict["ParamIndex"])
            
            # 随后选择array类型的参数
            if candidate_taint_data_indexs == []:
                for param_dict in arg_map:
                    if self.maybe_taint_data(param_dict["ParamType"], param_dict["ParamDefault"], need_array = True):
                        candidate_taint_data_indexs.append(param_dict["ParamIndex"])
            
            # 还是没找到时,直接选择第一个参数
            if candidate_taint_data_indexs == []:
                for param_dict in arg_map:
                    candidate_taint_data_indexs.append(param_dict["ParamIndex"])
                    break
            candidate_taint_data_indexs = sorted(list(set(candidate_taint_data_indexs)))
            # 返回结果
            if candidate_taint_data_indexs:
                return candidate_taint_data_indexs[0]
            else:
                return None
        
        def construct_new_arg_map(arg_map: list, taint_data_index):
            new_arg_map = []
            hava_used_quote = False
            if taint_data_index is not None:
                for param_dict in arg_map:
                    need_add = True
                    new_arg = {
                        "argIndex": str(param_dict["ParamIndex"]),
                        "argType": param_dict["ParamType"],
                        "argValue": None,
                    }
                    if str(param_dict["ParamIndex"]) == str(taint_data_index):
                        new_arg["argValue"] = self.TAINTED
                    elif (param_dict["ParamDefault"] is not None and param_dict["ParamDefault"] != "None") or (param_dict["ParamExample"] is not None and param_dict["ParamExample"] != "None"):
                        provided_value = param_dict["ParamDefault"] if (param_dict["ParamDefault"] is not None and param_dict["ParamDefault"] != "None") else param_dict["ParamExample"]
                        if self.is_global_string(provided_value):
                            need_add = False
                        elif provided_value.startswith("\"") and provided_value.endswith("\"") and not hava_used_quote:
                            hava_used_quote = True
                            new_arg["argValue"] = "\"" # 此处就让其处理常见的双引号即可
                        else:
                            new_arg["argValue"] = provided_value
                    
                    if need_add:
                        new_arg_map.append(new_arg)
            return new_arg_map

        # 下载PHP内置函数信息
        if not os.path.exists(self.built_in_api_dir):
            built_in_root = crawl_php_doc()
            self.built_in_api_dir = built_in_root
        # 开始分析
        new_sanitizer_info = {}
        new_func_arg_map_path = os.path.join(self.experiment_dir, "processed_built_in_functions_arg_map.json")
        # 获取所有内置函数的信息
        sanitizer_info = self.get_selected_functions_info()
        # 逐一处理所有内置函数
        for method_name in sanitizer_info.keys():
            arg_map = sanitizer_info[method_name]
            # 选定污点数据的索引
            taint_data_index = get_taint_index(arg_map)
            # 重新构造参数列表
            new_sanitizer_info[method_name] = construct_new_arg_map(arg_map, taint_data_index)
        # 存储最新的参数配置
        with open(new_func_arg_map_path, "w", encoding = "utf-8") as file:
            json.dump(new_sanitizer_info, file, ensure_ascii = False, indent = 4)
        
        for method_name in new_sanitizer_info.keys():
            result = {}
            try:
                error_flag, result = self.test_sanitizer_by_feature_strings(ExecuteFileType.PHP, method_name, new_sanitizer_info[method_name], is_user_defined = False)
            except:
                pass
            
            self.output_result(method_name, result)
        # 删除临时文件夹
        shutil.rmtree(self.built_in_api_dir)

    def test_all_user_defined_apis(self):
        """
        测试所有用户定义的API的污点清理能力
        """
        # 读取用户定义的API信息
        user_defined_func_arg_map = {}
        user_defined_func_arg_map_path = os.path.join(self.experiment_dir, "processed_user_defined_functions_arg_map.json")
        if os.path.exists(user_defined_func_arg_map_path):
            with open(user_defined_func_arg_map_path, "r", encoding = "utf-8") as file:
                user_defined_func_arg_map = json.load(file)
        # 逐一处理所有用户定义的API
        for method_name in user_defined_func_arg_map.keys():
            result = {}
            try:
                error_flag, result = self.test_sanitizer_by_feature_strings(ExecuteFileType.PHP, method_name, user_defined_func_arg_map[method_name], is_user_defined = True)
            except Exception as e:
                # raise e
                pass
                
            self.output_result(method_name, result)

if __name__ == "__main__":
    executor = CodeExecutor()
    # executor.test_all_built_in_apis()
    executor.test_all_user_defined_apis()