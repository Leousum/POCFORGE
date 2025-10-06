class StmtType(enumerate):
    '''
    Stmt节点类型
    '''
    # 13种基础 Stmt 类型
    CONTROL_STRUCTURE = "ControlStructure"       # 控制结构
    OBJECT = "Object"                            # 对象
    VARIABLE = "Variable"                        # 变量
    OBJECT_FIELD = "Object_Field"                # 对象属性
    LITERAL = "Literal"                          # 字面量
    OPERATION = "Operation"                      # 数据操作
    ASSIGNMENT = "Assignment"                    # 赋值语句
    OBJECT_CALL = "ObjCall"                      # 对象的函数调用
    COMMON_CALL = "CommonCall"                   # 变量的函数调用
    OBJECT_METHOD = "ObjMethod"                  # 对象的方法
    COMMON_METHOD = "CommonMethod"               # 普通方法
    METHOD_RETURN = "MethodReturn"               # 方法返回值
    TEMPORARY = "Temporary"                      # 临时节点

    # PHP 特殊类型
    PHP_ARRAY = "PHPArray"                       # PHP Array