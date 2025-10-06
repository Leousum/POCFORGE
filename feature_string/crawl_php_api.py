import os
import json
import shutil
import tarfile
import requests
from typing import List
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils
from datetime import datetime, timezone, timedelta

warning_api_file_paths = set()
built_in_root = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "Built_In_APIs", "Origin") # TODO: 此路径可能需要调整
php_manual_root = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")), "php_manual") # TODO: 此路径可以不用理会

def normal_content(content: str):
    if content:
        content = content.replace("\n", " ")
        content = content.replace("  ", " ").replace("  ", " ").replace("  ", " ")
        content = content.replace("    ", "")
        # content = content.replace("<", "&lt;").replace(">", "&gt;")
        content = saxutils.escape(content)
    return content

def parse_span_element(span_element):
    code_str = ""
    child_spans = span_element.find_all("span", recursive = False)
    if not child_spans:
        span_str = str(span_element)
        code_str = span_str[span_str.find(">") + 1:span_str.rfind("<")]
        code_str = code_str.replace("<br/>", "\n").replace("<br>", "\n").replace("</br>", "").replace("&lt;", "<").replace("&gt;", ">")
        return code_str
    else:
        for child_span in child_spans:
            code_str += parse_span_element(child_span)
        return code_str

def store_function_info(method_name,other_names,method_des,method_detail,php_versions,signatures,parameters,method_return,warning,examples):
    '''
    存储方法信息
    '''
    def generate_class_name(method_name, other_names: list):
        '''
        生成类名标签
        '''
        if method_name.find("::") != -1:
            if method_name.find("::") != -1:
                return method_name.split("::")[0]
        for name in other_names:
            if name:
                if name.find("::") != -1:
                    return name.split("::")[0]
        return None
    
    def generate_other_names(other_names: list):
        '''
        生成别名标签
        '''
        name = "\n"
        for other_name in other_names:
            name += f"""    <OtherName>{other_name}</OtherName>\n"""
        name = "" if name == "\n" else name.rstrip("\n")
        return name
    
    def generate_php_versions(php_versions: list):
        '''
        生成PHP Version标签列表
        '''
        vers = "\n"
        for php_version in php_versions:
            vers += f"        <PHPVersion>{normal_content(php_version)}</PHPVersion>\n"
        vers = "" if vers == "\n" else vers.rstrip("\n") # .replace("<", "&lt;").replace(">", "&gt;") # 此处不能处理转义符号,尖括号会造成XML文件存储失败
        return vers
    
    def generate_signatures(signatures: list):
        '''
        生成函数签名标签列表
        '''
        sigs = "\n"
        for signature in signatures:
            sigs += f"        <FunctionSignature>{normal_content(signature)}</FunctionSignature>\n"
        sigs = "" if sigs == "\n" else sigs.rstrip("\n")
        return sigs
    
    def generate_parameters(parameters: list):
        '''
        生成参数列表标签
        '''
        paras = '\n'
        for parameter in parameters:
            paras += f"""        <Parameter>
            <ParamType>{parameter.get('parameter_type', None)}</ParamType>
            <ParamIndex>{parameter.get('parameter_index', None)}</ParamIndex>
            <ParamName>{parameter.get('parameter_name', None)}</ParamName>
            <ParamDefault>{parameter.get('parameter_default', None)}</ParamDefault>
            <ParamDescription>{parameter.get('parameter_description', None)}</ParamDescription>
        </Parameter>\n"""
        paras = "" if paras == '\n' else paras.rstrip("\n")
        return paras

    def generate_code_path(root_dir: str):
        '''
        生成存储示例代码的文件路径
        '''
        num = 1
        code_path = os.path.join(root_dir, f"Code#{num}.php")
        while os.path.exists(code_path):
            num += 1
            code_path = os.path.join(root_dir, f"Code#{num}.php")
        return code_path

    def store_example_codes(root_dir: str, example_codes: List[dict]):
        '''
        存储示例代码
        '''
        for example_code in example_codes:
            if example_code:
                code_path = generate_code_path(root_dir)
                with open(code_path, "w") as file:
                    file.write(example_code)

    if method_name is None:
        return

    utc_now = datetime.now(timezone.utc)
    beijing_time = utc_now.astimezone(timezone(timedelta(hours=8)))
    sanitizer_xml_template = f"""<FunctionIdentifier>
    <ClassName>{generate_class_name(method_name, other_names)}</ClassName>
    <FunctionName>{method_name}</FunctionName>
    <OtherNames>{generate_other_names(other_names)}</OtherNames>
    <PHPVersions>{generate_php_versions(php_versions)}
    </PHPVersions>
    <FunctionSignatures>{generate_signatures(signatures)}
    </FunctionSignatures>
    <FunctionDescription>{method_des}</FunctionDescription>
    <FunctionDetail>{method_detail}</FunctionDetail>
    <Parameters>{generate_parameters(parameters)}
    </Parameters>
    <Return>
        <ReturnType>{method_return.get('return_type', None) if isinstance(method_return, dict) else None}</ReturnType>
        <ReturnDescription>{method_return.get('return_description', None) if isinstance(method_return, dict) else None}</ReturnDescription>
    </Return>
    <Warning>{warning}</Warning>
    <SanitizeConditions>
        <SanitizeCondition>
            <SanitizeDataType>清理的数据类型(字符串/序列化类/用户权限): InputString/InputObject/Authorization</SanitizeDataType>
            <SanitizeResult>清理结果如何处理?(作为返回值/直接退出/改变参数或调用者/改变外部数据): ReturnData/ExitProgram/ParamData/ExternalData</SanitizeResult>
            <SanitizeVulnTypes>
                <SanitizeVulnType>
                    <Type>清理的污点数据对应漏洞类型(目录穿越/命令注入/XSS/SQLi/CSRF/反序列化/授权/SSRF/所有): CWE-22/CWE-78/CWE-79/CWE-89/CWE-352/CWE-502/CWE-287/CWE-862/CWE-863/CWE-918/ALL</Type>
                    <SanitizeLevel>清理能力评级(低/中/高): low/medium/high</SanitizeLevel>
                </SanitizeVulnType>
            </SanitizeVulnTypes>
            <SanitizeParameters> <!-- 代码片段可以清理的参数信息 -->
                <SanitizeParameter>
                    <ParamType>类型</ParamType>
                    <ParamIndex>索引(从0开始,0代表调用者,1代表第1个参数)</ParamIndex>
                    <ParamName>形参名称</ParamName>
                </SanitizeParameter>
            </SanitizeParameters>
            <SanitizeDataInfos> <!-- 代码片段可以清理的数据信息 -->
                <SanitizeDataInfo>
                    <DataType>数据类型</DataType>
                    <DataName>数据名称</DataName>
                </SanitizeDataInfo>
            </SanitizeDataInfos>
            <SanitizeStrs>
                <SanitizeALL>是否可以清理所有输入: true/false</SanitizeALL>
                <SanitizeStr>可清理的字符串常量</SanitizeStr>
            </SanitizeStrs>
            <SanitizeObjs>
                <SanitizeALL>是否可以清理所有输入: true/false</SanitizeALL>
                <SanitizeObj>可以清理的类</SanitizeObj>
            </SanitizeObjs>
            <ParamConditions> <!-- 函数或代码片段具备清理能力时,此函数参数所应满足的约束条件 -->
                <ParamCondition>
                    <ParamType>类型</ParamType>
                    <ParamIndex>索引(从0开始,0代表调用者,1代表第1个参数)</ParamIndex>
                    <ParamName>形参名称</ParamName>
                    <Condition>约束条件</Condition>
                </ParamCondition>
            </ParamConditions>
            <DataConditions> <!-- 函数具备清理能力时,相关数据所应满足的约束条件 -->
                <DataCondition>
                    <DataType>数据类型</DataType>
                    <DataName>数据名称</DataName>
                    <Condition>约束条件</Condition>
                </DataCondition>
            </DataConditions>
        </SanitizeCondition>
    </SanitizeConditions>
    <TransferConditions>
        <TransferCondition>
        </TransferCondition>
    </TransferConditions>
    <SourceConditions>
        <SourceCondition>
        </SourceCondition>
    </SourceConditions>
    <SinkConditions>
        <SinkCondition>
        </SinkCondition>
    </SinkConditions>
    <AddTime>{beijing_time.strftime("%Y-%m-%d %H:%M:%S")}</AddTime>
</FunctionIdentifier>
"""
    # 保存模板至指定目录
    root = ET.ElementTree(ET.fromstring(sanitizer_xml_template))
    # 写入XML文件
    try:
        xml_dir = os.path.join(built_in_root, method_name)
        if not os.path.exists(xml_dir):
            os.makedirs(xml_dir, mode = 0o777)
        xml_path = os.path.join(xml_dir, "Rule.xml")
        with open(xml_path, "wb") as file:
            file.write(ET.tostring(root.getroot(), encoding = 'utf-8'))
        store_example_codes(xml_dir, examples)
        if warning:
            warning_api_file_paths.add(xml_path)
        # print(f"成功生成模板XML文件! 可查看: {xml_path}")
    except Exception as e:
        # print("请检查输入!")
        raise(e)

def download_php_doc():
    '''
    下载并解压PHP官方文档
    '''
    url = "https://www.php.net/distributions/manual/php_manual_en.tar.gz"
    print(f"正在下载PHP官方文档,网址: {url}")
    if not os.path.exists(php_manual_root):
        os.makedirs(php_manual_root)
    
    tar_path = os.path.join(php_manual_root, "manual.tar.gz")
    if not os.path.exists(tar_path):
        # 下载文件
        response = requests.get(url, stream=True)
        with open(tar_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
    # 解压文件
    with tarfile.open(tar_path) as tar:
        tar.extractall(path=php_manual_root)
    print(f"文档下载成功,存储路径: {php_manual_root}")
    return os.path.join(php_manual_root, "php-chunked-xhtml")

def parse_function_file(file_path):
    '''
    解析HTML文件
    '''
    soup = None
    with open(file_path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'html.parser')
    if soup is None:
        return

    # (1) 解析函数名称
    method_name = None
    other_names = []
    refnames = soup.find_all('h1', class_ = 'refname')
    if refnames:
        for refname in refnames:
            if not method_name:
                method_name = refname.text.strip()
            else:
                other_names.append(refname.text.strip())
    if not method_name:
        return
    
    if method_name and other_names:
        if method_name.find("::") != -1:
            for other_name in other_names:
                if other_name.find("::") == -1:
                    other_names.remove(other_name)
                    other_names.append(method_name)

                    temp_name = method_name
                    method_name = other_name
                    other_name = temp_name
                    break
    other_names = list(set(other_names))

    # (2) 解析函数用途
    method_description = None
    dc_title = soup.find('p', class_ = 'dc-title')
    if dc_title:
        method_description = dc_title.text.strip()
    method_description = normal_content(method_description)
    
    # (3) 解析详细说明
    method_detail = None
    detail = soup.find('p', class_ = 'para rdfs-comment')
    if detail:
        method_detail = detail.text.strip()
    method_detail = normal_content(method_detail)

    # (4) 解析PHP版本
    php_versions = []
    verinfo = soup.find('p', class_='verinfo')
    if verinfo:
        php_versions = verinfo.text.strip().replace('(', '').replace(')', '').split(", ")
    
    # (5) 解析函数签名
    signatures = []
    methodsynopsis = soup.find_all('div', class_='methodsynopsis dc-description')
    if methodsynopsis:
        for methodsynopsi in methodsynopsis:
            sig = methodsynopsi.text.replace("\n", "").strip()
            sig = normal_content(sig)
            if sig:
                signatures.append(sig)
    
    # (6) 解析参数信息
    parameters: List[dict] = []
    parameter_list = ""
    for signature in signatures:
        if not parameter_list:
            parameter_list = signature[signature.find('(') + 1:signature.rfind(')')]
        elif signature.find("::") != -1:
            parameter_list = signature[signature.find('(') + 1:signature.rfind(')')]
            break
    if parameter_list.find(", ") != -1:
        parameter_list = parameter_list.split(", ")
    elif parameter_list.find(",") != -1:
        parameter_list = parameter_list.split(",")
    elif parameter_list:
        parameter_list = [parameter_list]
    else:
        parameter_list = []
    parameter_div = soup.find('div', class_ = 'refsect1 parameters')
    if parameter_div:
        parameter_dts = parameter_div.find_all("dt")
        parameter_dds = parameter_div.find_all("dd")
        index = 0
        for parameter_dt, parameter_dd in zip(parameter_dts, parameter_dds):
            index += 1
            parameter_index = index
            parameter_type = None
            parameter_name = None
            if parameter_dt.find('code'):
                parameter_name = '$' + parameter_dt.find('code').text.strip()
            elif parameter_dt: 
                parameter_name = '$' + parameter_dt.text.strip()
            if not parameter_name or parameter_name == '$':
                continue
            parameter_default = None
            parameter_description = parameter_dd.text.strip()
            for para_name in parameter_list:
                if para_name.find(parameter_name) != -1:
                    parameter_type = para_name.split()[0]
                    if para_name.find("=") != -1:
                        parameter_default = para_name[para_name.find("=") + 1:]
                    break
            parameters.append(
                {
                    "parameter_index": parameter_index,
                    "parameter_type": parameter_type,
                    "parameter_name": normal_content(parameter_name),
                    "parameter_default": normal_content(parameter_default),
                    "parameter_description": normal_content(parameter_description)
                }
            )

    # (7) 解析返回值
    return_type = None
    for signature in signatures:
        return_type = signature[signature.rfind(":") + 1:]
    return_description = ''
    return_div = soup.find('div', class_ = 'refsect1 returnvalues')
    if return_div:
        return_ps = return_div.find_all('p')
        for return_p in return_ps:
            return_description += return_p.text.strip()
    method_return = {"return_type": return_type, "return_description": normal_content(return_description)}

    # (8) 获取示例程序
    examples = []
    example_div = soup.find('div', class_ = "refsect1 examples")
    if example_div:
        example_code_elements = example_div.find_all("code")
        for code_element in example_code_elements:
            if code_element:
                example_content = ""
                span_elements = code_element.find_all("span", recursive = False)
                for span_element in span_elements:
                    code_str = parse_span_element(span_element)
                    # print(code_str)
                    example_content += code_str
                
                if example_content:
                    examples.append(example_content)

    # (9) 获取警告信息
    warning = None
    warning_div = soup.find('div', class_ = "warning")
    if not warning_div:
        warning_div = soup.find('div', class_ = "caution")
    if warning_div:
        warning = warning_div.text.strip()
        warning = normal_content(warning)
        # TODO: 此处可能还需要补充关键字
        not_security_contents = ["deprecated", "currently not documented", "is experimental", "this function work only in", "this function has been removed", "this function was removed"]
        if warning:
            for not_security_content in not_security_contents:
                if warning.lower().find(not_security_content) != -1:
                    warning = None
                    break

    # (10) 存储所有信息
    store_function_info(method_name, other_names, method_description, method_detail, php_versions, signatures, parameters, method_return, warning, examples)

def process_doc(manual_path):
    '''
    遍历所有函数文件
    '''
    for root, dirs, files in os.walk(manual_path):
        for file in files:
            if file.endswith(".html"):
                # if file.startswith("function.")
                file_path = os.path.join(root, file)
                # print(f"Processing: {file_path}")
                try:
                    parse_function_file(file_path)
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
                    raise(e)

def crawl_php_doc():
    manual_dir = download_php_doc()
    process_doc(manual_dir)
    shutil.rmtree(php_manual_root)
    return built_in_root