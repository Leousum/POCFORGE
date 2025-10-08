from static_analysis.pfg.node_status import NodeStatus

class PFGNode():
    def __init__(self, code_block_id = None, node_type = None, parent_type = None, parent_identifier = None, own_type = None, identifier = None, value = None, is_class = False) -> None:
        self.pfg_id = None
        self.code_block_id = code_block_id # 所属代码块id,用于区分全局和局部变量(类似于C++的namespace)
        self.node_type = node_type # e.g."Object","Object_Field","Variable","Index","Temporary"
        self.parent_type = parent_type # e.g."Student","Teacher"(该节点父节点的类型,一个节点的父节点并不一定是指向它的节点)
        self.parent_identifier = parent_identifier
        # self.parent_pfg_id = None # 父节点的pfg_id
        self.parent_signature = None # 父节点的signature
        self.own_type = own_type # e.g."Student","Teacher" or "java.util.String"(该节点自身的类型)
        self.identifier = identifier # e.g."student","teacher","x"(该节点的标识符)
        self.value = value # e.g."leousum",24 (在joern.py文件中,已经做了类型转换处理)
        self.signature = None # 节点签名
        self.short_signature = None # 节点短签名(在获取节点的值时会用到)
        self.is_class = is_class # 该节点是否是一个类
        self.status = set() # 记录节点状态
        self.status.add(NodeStatus.UNTAINTED)
        # self.points2sets = set() # 数据流 A --> B
        # self.fields = set() # 属性 obj --> field
        self.attributes = list() # 属性映射列表
        self.update_signature()
    
    def update_signature(self):
        self.signature = f"<[{self.node_type}] {self.code_block_id}: {self.parent_type}: {self.parent_identifier}: {self.own_type}: {self.identifier}>"
        self.short_signature = f"<[{self.parent_type}: {self.own_type}: {self.identifier}>"
    
    # def add_field(self, node):
    #     self.fields.add(node.pfg_id)
    #     # node.parent_pfg_id = self.pfg_id

    # def add_data_flow(self, node):
    #     self.points2sets.add(node.pfg_id)

    def to_string(self):
        taint_status = "(Not Tainted)"
        if NodeStatus.TAINTED in self.status:
            taint_status = "(Tainted)"
        return (f"{self.signature} = {self.value} {taint_status}")

class PFGNode_Type(enumerate):
    '''
    PFG节点类型
    '''
if __name__ == "__main__":
    test = PFGNode(
        code_block_id = 10,
        node_type = "Index",
        parent_type = "double[]",
        parent_identifier = "student.score",
        own_type = "int",
        identifier = 1,
        value = None,
        is_class = False
    )
    print(test.signature)