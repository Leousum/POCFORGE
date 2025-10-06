class NodeType(enumerate):
    '''
    CPG节点类型
    '''
    ALL = "all"
    ASSIGNMENT = "assignment"
    BLOCK = "block"
    CALL = "call"
    COMMENT = "comment"
    CONTROL_STRUCTURE = "controlStructure"
    FILE = "file"
    IDENTIFIER = "identifier"
    LITERAL = "literal"
    LOCAL = "local"
    MEMBER = "member"
    META_DATA = "metaData"
    METHOD = "method"
    METHOD_REF = "methodRef"
    METHOD_RETURN = "methodReturn"
    MODIFIER = "modifier"
    NAMESPACE_BLOCK = "namespaceBlock"
    TYPE_DECL = "typeDecl"

class NodeField(enumerate):
    '''
    CPG节点属性
    '''
    # CPG节点一级属性: 这些属性可以继续链式调用其他属性。
    ARGUMENT = "argument"
    RECEIVER = "receiver"
    RETURNS = "returns"
    TARGET = "target"
    TYP = "typ"
    TYPE_REF = "typeRef"
    NAMESPACE = "namespace"
    TAG = "tag"
    AST = "ast"
    AST_CHILDREN = "astChildren"
    AST_PARENT = "astParent"
    AST_IN = "_astIn"
    CFG_IN = "_cfgIn"
    CFG_OUT= "_cfgOut"
    CFG_NEXT = "cfgNext"
    LOCATION = "location"
    CALLER = "caller"
    CALLEE = "callee"
    IN_CALL = "inCall"
    CALL_IN = "callIn"
    CONTROLS = "controls"
    CONDITION = "condition"
    CONTROLLED_BY = "controlledBy"
    DOMINATES = "dominates"
    DOMINATED_BY = "dominatedBy"
    PARAMETER = "parameter"
    POST_DOMINATES = "postDominates"
    POST_DOMINATED_BY = "postDominatedBy"
    FLOWS = "flows"
    SOURCE = "source"
    SINK = "sink"
    REACHABLE_BY = "reachableBy"
    REACHABLE_BY_FLOWS = "reachableByFlows"
    REACHING_DEF_IN= "_reachingDefIn"
    REACHING_DEF_OUT= "_reachingDefOut"

    # CPG节点二级属性: 这些属性返回标量值,不能继续链式调用
    ID = "id"
    LABEL = "_label"
    NAME = "name"
    CODE = "code"
    CLASS_SHORT_NAME = "classShortName"
    FILE_NAME = "fileName"
    FULL_NAME = "fullName"
    SIGNATURE = "signature"
    IS_EXTERNAL = "isExternal"
    ORDER = "order"
    VALUE = "value"
    INDEX = "index"
    LANGUAGE = "language"
    VERSION = "version"
    TYPE_FULL_NAME = "typeFullName"
    CONTROL_STRUCTURE_TYPE = "controlStructureType"
    ARGUMENT_INDEX = "argumentIndex"
    ARGUMENT_NAME = "argumentName"
    AST_PARENT_FULL_NAME = "astParentFullName"
    AST_PARENT_TYPE = "astParentType"
    METHOD_FULL_NAME = "methodFullName"
    METHOD_SHORT_NAME = "methodShortName"
    INHERITS_FROM_TYPEFULLNAME="inheritsFromTypeFullName"
    INHERITS_FROM_OUT = "_inheritsFromOut"
    DYNAMIC_TYPE_HINT_FULL_NAME = "dynamicTypeHintFullName"

    # 位置属性,仅作为location的子属性
    LINE_NUMBER = "lineNumber"
    LINE_NUMBER_END = "lineNumberEnd"

class NodeConstraint(enumerate):
    '''
    CPG节点查询结果的限制条件
    '''

    # 节点类型检查
    IS_CALL = "isCall"
    IS_OBJ_CALL = "isObjCall"
    IS_COMMON_CALL = "isCommonCall"
    IS_IDENTIFIER = "isIdentifier"
    IS_LITERAL = "isLiteral"
    IS_METHOD = "isMethod"
    IS_CONTROL_STRUCTURE = "isControlStructure"
    IS_BLOCK = "isBlock"
    IS_TYPE_DECL = "isTypeDecl"
    IS_TYPE_REF = "isTypeRef"
    IS_METHOD_REF = "isMethodRef"
    IS_METHOD_RETURN = "isMethodReturn"
    IS_MEMBER = "isMember"
    IS_COMMENT = "isComment"
    IS_NAMESPACE_BLOCK = "isNamespaceBlock"
    IS_FILE = "isFile"
    IS_PARAMETER = "isParameter"
    IS_LOCAL = "isLocal"
    IS_RETURN = "isReturn"

    # 访问修饰符检查
    IS_PUBLIC = "isPublic"
    IS_PRIVATE = "isPrivate"
    IS_PROTECTED = "isProtected"
    IS_STATIC = "isStatic"

    # 其他属性检查
    IS_EXTERNAL = "isExternal"
    IS_DYNAMIC = "isDynamic"
    IS_VIRTUAL = "isVirtual"

class NodeMethod(enumerate):
    '''
    CPG查询函数
    '''
    CONTAINS = "contains"
    DEDUP = "dedup"
    FILTER = "filter"
    MAP = "map"
    SORT_BY = "sortBy"
    STARTS_WITH = "startsWith"
    REPEAT = "repeat"
    UNTIL = "until"

class NodeLabel(enumerate):
    '''
    CPG Node的_label属性
    '''
    BLOCK = "BLOCK"
    CALL = "CALL"
    CONTROL_STRUCTURE = "CONTROL_STRUCTURE"
    FIELD_IDENTIFIER = "FIELD_IDENTIFIER"
    IDENTIFIER = "IDENTIFIER"
    LITERAL = "LITERAL"
    METHOD = "METHOD"
    METHOD_RETURN = "METHOD_RETURN"
    MEMBER = "MEMBER"
    METHOD_PARAMETER_IN = "METHOD_PARAMETER_IN"
    METHOD_PARAMETER_OUT = "METHOD_PARAMETER_OUT"
    TYPE_DECL = "TYPE_DECL"
    TYPE_REF = "TYPE_REF"
    RETURN = "RETURN"
    JUMP_TARGET = "JUMP_TARGET"

class NodeOperator(enumerate):
    '''
    CPG Node的methodFullName属性中的所有运算符号
    '''
    # 通用运算
    ALLOC = "<operator>.alloc" # 地址分配
    ASSIGNMENT = "<operator>.assignment" # 赋值语句
    CAST = "<operator>.cast" # 强制类型转换
    FieldAccess = "<operator>.fieldAccess" # 属性访问
    IndexAccess = "<operator>.indexAccess" # 索引访问
    CONDITIONAL = "<operator>.conditional" # 三元运算符

    # 加减乘除,自加,自减等数值运算
    PLUS = "<operator>.plus"
    ADDITION = "<operator>.addition"
    MINUX = "<operator>.minus"
    SUBTRACTION = "<operator>.subtraction"
    DIVISION = "<operator>.division"
    FLOOR_DIV = "<operator>.floorDiv"
    MODULO = "<operator>.modulo"
    MULTIPLICATION = "<operator>.multiplication"
    EXPONENTIATION = "<operator>.exponentiation"
    ASSIGNMENT_PLUS = "<operator>.assignmentPlus"
    ASSIGNMENT_DIVISION = "<operator>.assignmentDivision"
    ASSIGNMENT_MINUS = "<operator>.assignmentMinus"
    ASSIGNMENT_MODULO = "<operators>.assignmentModulo"
    ASSIGNMENT_MULTIPLICATION = "<operator>.assignmentMultiplication"
    POST_INCREMENT = "<operator>.postIncrement"
    POST_DECREMENT = "<operator>.postDecrement"
    PRE_INCREMENT = "<operator>.preIncrement"
    PRE_DECREMENT = "<operator>.preDecrement"
    SHIFT_LEFT = "<operator>.shiftLeft" # 左移操作
    ARITHMETIC_SHIFT_RIGHT = "<operator>.arithmeticShiftRight" # 右移操作

    # 两数比较运算
    EQUALS = "<operator>.equals"
    NOT_EQUALS = "<operator>.notEquals"
    LESS_THAN = "<operator>.lessThan"
    GREATER_THAN = "<operator>.greaterThan"
    LESS_EQUALS_THAN = "<operator>.lessEqualsThan"
    GREATER_EQUALS_THAN = "<operator>.greaterEqualsThan"

    # 字符串操作
    CONCAT = "<operator>.concat"
    ASSIGNMENT_CONCAT = "<operator>.assignmentConcat"

    # 与或非逻辑操作
    AND = "<operator>.and"
    OR = "<operator>.or"
    NOT = "<operator>.not"
    XOR = "<operator>.xor"
    LOGIC_AND = "<operator>.logicalAnd"
    LOGIC_OR = "<operator>.logicalOr"
    LOGIC_NOT = "<operator>.logicalNot"

    # PHP独有操作
    COALESCE = "<operator>.coalesce" #   空合并操作符 ??