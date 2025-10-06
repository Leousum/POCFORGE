import os
import json
import subprocess

def is_num(str_index: str):
    try:
        index = int(str_index)
        return True
    except:
        return False

def get_function_name(signature: str):
    return signature[signature.find(" ") + 1:signature.find("(")]

def construct_php_code(base_var, call_code, root_path):
    php_code = "<?php\n"
    if base_var is not None:
        if isinstance(base_var, str):
            mark_str = "\""
            if base_var.find("\"") != -1:
                mark_str = "\'"
            php_code += f"""$base = {mark_str + base_var + mark_str};\n"""
        else:
            php_code += f"""$base = {str(base_var)};\n"""
        php_code += f"""$result = $base.{call_code};\n"""
        php_code += f"""$data = array("base" => $base, "result" => $result);\n"""
        php_code += f"""echo json_encode($data);\n"""
    else:
        php_code += f"""$result = {call_code};\n"""
        php_code += f"""$data = array("result" => $result);\n"""
        php_code += f"""echo json_encode($data);\n"""
    php_code += f"""?>"""
    code_path = os.path.join(root_path, f"temp.php")
    with open(code_path, "w") as file:
        file.write(php_code)
    return "php", code_path

def construct_python_code(base_var, call_code, root_path):
    python_code = "import json\n"
    if base_var is not None:
        if isinstance(base_var, str):
            mark_str = "\""
            if base_var.find("\"") != -1:
                mark_str = "\'"
            python_code += f"""base = {mark_str + base_var + mark_str}\n"""
        else:
            python_code += f"""base = {str(base_var)}\n"""
        python_code += f"""result = base.{call_code}\n"""
        python_code += f"""data = dict()\n"""
        python_code += f"""data['base'] = base\n"""
        python_code += f"""data['result'] = result\n"""
        python_code += f"""print(json.dumps(data))\n"""
    else:
        python_code += f"""result = {call_code}\n"""
        python_code += f"""data = dict()\n"""
        python_code += f"""data['result'] = result\n"""
        python_code += f"""print(json.dumps(data))\n"""
    code_path = os.path.join(root_path, f"temp.py")
    with open(code_path, "w") as file:
        file.write(python_code)
    return "python3", code_path

def construct_java_code(base_var, call_code, root_path):
    java_code = """
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class temp {
    private Map<String, Object> jsonMap;
    public temp() {
        jsonMap = new HashMap<>();
    }
    public void put(String key, Object value) {
        jsonMap.put(key, value);
    }
    public Object get(String key) {
        return jsonMap.get(key);
    }
    public Set<String> keySet() {
        return jsonMap.keySet();
    }
    @Override
    public String toString() {
        StringBuilder json = new StringBuilder("{");
        for (String key : jsonMap.keySet()) {
            json.append("\\\"").append(key).append("\\\":");
            Object value = jsonMap.get(key);
            if (value instanceof String) {
                json.append("\\\"").append(value).append("\\\"");
            } else {
                json.append(value);
            }
            json.append(",");
        }
        if (json.length() > 1) {
            json.deleteCharAt(json.length() - 1);
        }
        json.append("}");
        return json.toString();
    }
    public static void main(String[] args) {
        temp data = new temp();
"""
    if base_var is not None:
        if isinstance(base_var, str):
            mark_str = "\""
            if base_var.find("\"") != -1:
                mark_str = "\'"
            java_code += f"""        String base = {mark_str + base_var + mark_str};\n"""
        elif isinstance(base_var, int):
            java_code += f"""        int base = {str(base_var)};\n"""
        elif isinstance(base_var, float):
            java_code += f"""        double base = {str(base_var)};\n"""
        elif isinstance(base_var, bool):
            java_code += f"""        boolean base = {str(base_var).lower()};\n"""
        else:
            return None, None
        java_code += f"""        data.put("result", base.{call_code});\n"""
        java_code += f"""        System.out.println(data.toString());\n"""
        java_code += """    }\n"""
        java_code += """}\n"""
    else:
        java_code += f"""        data.put("result", {call_code});\n"""
        java_code += f"""        System.out.println(data.toString());\n"""
        java_code += """    }\n"""
        java_code += """}\n"""
    code_path = os.path.join(root_path, f"temp.java")
    with open(code_path, "w") as file:
        file.write(java_code)
    return "java", code_path

def process_func(filepath: str, func_name: str, arguments_map: dict):
    error_flag = True
    result = dict()
    filepath = filepath.lower()
    # 获取函数调用者
    base_var = None
    if "0" in arguments_map.keys():
        base_var = arguments_map["0"]
    # 获取函数调用语句
    call_code = ""
    call_code = call_code + func_name + "("
    for argument_index in arguments_map.keys():
        if argument_index != "0":
            if not is_num(argument_index):
                call_code = call_code + argument_index + "="
            if isinstance(arguments_map[argument_index], str):
                mark_str = "\""
                if arguments_map[argument_index].find("\"") != -1:
                    mark_str = "\'"
                call_code = call_code + mark_str + arguments_map[argument_index] + mark_str + ","
            else:
                call_code = call_code + str(arguments_map[argument_index]) + ","
    call_code = call_code.strip(",") + ")"
    # 构造源码
    interpreter = None
    code_path = None
    root_path = os.path.abspath(os.path.join(os.path.dirname(__file__)))
    if filepath.endswith(".php"):
        interpreter, code_path = construct_php_code(base_var, call_code, root_path)
    elif filepath.endswith(".java"):
        interpreter, code_path = construct_java_code(base_var, call_code, root_path)
    elif filepath.endswith(".py"):
        interpreter, code_path = construct_python_code(base_var, call_code, root_path)
    # 执行语句
    if code_path is not None and interpreter is not None:
        run_function = subprocess.run([interpreter, code_path], capture_output = True, text = True)
        os.remove(code_path)
        if run_function.returncode == 0:
            error_flag = False
            result = json.loads(run_function.stdout)
    return error_flag, result

if __name__ == "__main__":
    # error_flag, result = process_func(
    #     filepath = "test.php",
    #     func_name = "addslashes",
    #     arguments_map = {
    #         "1": 'Shanghai is the "biggest" city in China.'
    #     }
    # )
    error_flag, result = process_func(
        filepath = "test.java",
        func_name = "String.format",
        arguments_map = {
            "1": "%s to the Ultimate Question of Life, the Universe, and Everything is %d.",
            "2": "Answer",
            "3": 42
        }
    )
    # error_flag, result = process_func(
    #     filepath = "test.py",
    #     func_name = "int",
    #     arguments_map = {
    #         "1": "123456"
    #     }
    # )
    print(error_flag)
    print(result)
    print(type(result["result"]))