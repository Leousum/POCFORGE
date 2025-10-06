class NodeStatus(enumerate):
    '''
    节点状态
    '''
    TAINTED = "Tainted"              # 被污染
    UNTAINTED = "Not Tainted"          # 未被污染