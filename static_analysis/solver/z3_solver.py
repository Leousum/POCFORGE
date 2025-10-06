import time
from z3 import z3
from z3 import sat
from z3 import Solver
from z3.z3 import Int
from z3.z3 import String
from z3.z3 import Length
from z3.z3 import Contains
from z3.z3 import SubString
from z3.z3 import Not
from z3.z3 import And
from z3.z3 import Or
from z3.z3 import Implies
from z3.z3 import ForAll
from z3.z3 import Extract
from z3.z3 import StringVal
from z3.z3 import IndexOf
from z3.z3 import If
from z3.z3 import Replace

class Z3Solver():
    def __init__(self) -> None:
        pass

    # ======================================= Function Model Start =======================================
    def translate_htmlspecialchars(self, arguments_map: dict, existing_constraints = None):
        # php htmlspecialchars(): filter HTML special characters
        arg_string = None
        arg_flags = "ENT_COMPAT" # 默认编码方式
        if "1" in arguments_map.keys():
            arg_string = arguments_map["1"]
        if "2" in arguments_map.keys():
            arg_flags = arguments_map["2"]
        z3.set_option("smt.string_solver", "z3str3")
        solver = Solver()
        if existing_constraints is not None:
            solver.from_string(existing_constraints) # 导入已有约束条件
        res = String(arg_string)
        if arg_flags == "ENT_COMPAT":
            pass
        elif arg_flags == "ENT_QUOTES":
            pass
        elif arg_flags == "ENT_NOQUOTES":
            pass

    # ======================================= Function Model End =======================================

    def solve_strpos(self, arguments_map: dict, relation: str, compare_result: bool): # operator = None, operation_result = None
        # php strpos(): determines whether it contains substring
        # get arguments
        str1 = None; str2 = None
        if "1" in arguments_map.keys():
            str1 = arguments_map["1"]
        if "2" in arguments_map.keys():
            str2 = arguments_map["2"]
        # compute expression
        result = None
        if str1 is not None and str2 is not None:
            z3.set_option("smt.string_solver", "z3str3")
            solver = Solver()
            res = String(str1)
            if (relation == "==" and compare_result) or (relation == "!==" and (not compare_result)):
                solver.add(Contains(res, str2))
            else:
                solver.add(Not(Contains(res, str2)))
            if solver.check() == sat:
                model = solver.model()
                result = model[res]
        return result
    
    def solve_strlen(self, arguments_map: dict, relation: str, compare_result: str):
        # php strlen(): get the length of a string
        # get arguments
        str1 = None
        if "1" in arguments_map.keys():
            str1 = arguments_map["1"]
        # compute expression
        result = None
        if str1 is not None and compare_result is not None:
            z3.set_option("smt.string_solver", "z3str3")
            solver = Solver()
            res = String(str1)
            constraint = f"Length(res) {relation} {compare_result}"
            solver.add(eval(constraint))
            if solver.check() == sat:
                model = solver.model()
                result = model[res]
        return result
    
    def preg_match(self):
        # 创建字符串变量
        s = String('s')
        # 创建Z3求解器
        solver = Solver()
        # 限制字符串的长度至少为1
        constraint = Length(s) >= 1
        # 创建一个表达式来检查字符串的每个字符是否为数字
        # 使用递归来处理未知长度的字符串
        i = Int('i')  # 创建整数变量来模拟索引
        constraint = And(constraint, ForAll(i, Implies(And(i >= 0, i < Length(s)), And(Extract(s, i, 1) >= StringVal("0"), Extract(s, i, 1) <= StringVal("9")))))
        # 添加字符串 '12345678910' 作为约束来进行求解
        solver.add(constraint, s == StringVal("12345678910"))

        # 检查是否满足约束
        if solver.check() == sat:
            print("12345678910 satisfies the constraint")
        else:
            print("12345678910 does not satisfy the constraint")

    def preg_split(self):
        # 定义输入字符串
        input_string = StringVal("column1, column2, column3, column4")
        split_result = []  # 用于存储分割后的结果
        # 创建 Z3 求解器
        solver = Solver()
        # 起始位置
        start = 0
        index = 0
        num = 0
        # 迭代查找逗号和空格，并提取子字符串
        while True:
            num += 1
            print(f"开始添加第{num}轮的约束条件, start: {start}, index: {index}")
            input()
            # 查找下一个逗号的位置
            comma_pos = IndexOf(input_string, StringVal(","), start)
            # 如果没有找到逗号，说明剩下的部分是最后一个子字符串
            if comma_pos == -1:
                remaining_part = SubString(input_string, start, Length(input_string) - start)
                split_result.append(remaining_part)
                break
            # 检查逗号后是否有空格
            space_after_comma = If(SubString(input_string, comma_pos + 1, 1) == StringVal(" "), 1, 0)
            # 提取当前子字符串（从 start 到逗号位置前一个字符）
            part = SubString(input_string, start, comma_pos - start)
            split_result.append(part)
            # 更新起始位置，跳过逗号和可选空格
            start = comma_pos + 1 + space_after_comma
            index += 1
        # 为每个分割部分定义约束
        for i, part in enumerate(split_result):
            print(i)
            print(part)
            solver.add(part != "")
        # 检查并输出结果
        if solver.check() == sat:
            model = solver.model()
            result = [model.evaluate(part) for part in split_result]
            print("Split Result:", result)
        else:
            print("No solution found.")

if __name__ == "__main__":
    t1 = time.time()
    test = Z3Solver()
    # res1 = test.solve_strpos({"1": "returnto","2": "host.php"}, "==", True)
    # print(res1)
    # res2 = test.solve_strlen({"1": "returnto"}, ">=", "5")
    # print(res2)
    # test.preg_split()
    # Initializes the constraint solver
    z3.set_option("smt.string_solver", "z3str3")
    solver = Solver()
    # Define the string variable returnto
    returnto = String('returnto')
    solver.add(Contains(returnto, StringVal("host.php")))
    # Added escape rules for htmlspecialchars()
    #temp0 = String('temp0')
    # temp0 = Replace(returnto, StringVal("<"), StringVal("&lt;"))
    # #temp1 = String('temp1')
    # temp1 = Replace(temp0, StringVal(">"), StringVal("&gt;"))
    # #temp2 = String('temp2')
    # temp2 = Replace(temp1, StringVal("&"), StringVal("&amp;"))
    # #temp3 = String('temp3')
    # temp3 = Replace(temp2, StringVal("\""), StringVal("&quot;"))
    # #temp4 = String('temp4')
    # temp4 = Replace(temp3, StringVal("'"), StringVal("&#039;"))

    solver.add(Not(Contains(returnto, StringVal("<"))))
    solver.add(Not(Contains(returnto, StringVal(">"))))
    solver.add(Not(Contains(returnto, StringVal("&"))))
    solver.add(Not(Contains(returnto, StringVal("\""))))
    solver.add(Not(Contains(returnto, StringVal("'"))))

    # <,>,&,\",'等特殊字符

    # 简化版本
    # temp0 = String('temp0')
    # temp0 = Replace(
    #     Replace(
    #         Replace(
    #             Replace(
    #                 Replace(returnto, "<", "&lt;"),
    #                 ">", "&gt;"
    #             ),
    #             "&", "&amp;"
    #         ),
    #         "\"", "&quot;"
    #     ), 
    #     "'", "&#039;"
    # )
    # Add attack constraints for XSS payload
    # solver.add(Contains(returnto, StringVal("host.php")))
    solver.add(Or(
        Contains(returnto, StringVal("javascript:alert(1)")), 
        Contains(returnto, StringVal("<script>alert(1)</script>"))
    ))
    # solver.add(Contains(returnto, StringVal("javascript:alert(1)")))
    # solver.add(Contains(returnto, StringVal("//")))
    # solver.add(Contains(temp1, StringVal("javascript:alert(1)")))
    # Solve the constraints
    if solver.check() == sat:
        model = solver.model()
        print(model.eval(returnto).as_string())
        # print(model.eval(temp4).as_string())
    else:
        print("No Answer!")
    print(time.time() - t1)
    smt_string = solver.to_smt2()
    # 输出约束字符串
    print("生成的 SMT-LIB 字符串:")
    print(smt_string)