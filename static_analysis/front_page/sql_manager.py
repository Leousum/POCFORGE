import os

def parse_sql(sql_file_path: str, sql_structure: dict):
    # 解析SQL文件
    sql_content = ""
    with open(sql_file_path, "r", encoding = "utf-8") as f:
        sql_content = f.readlines()
    find_table = False
    table_name = None
    for content in sql_content:
        content = content.strip()
        if content.lower().startswith("create table"):
            find_table = True
            if content.find("`") != -1 and content.rfind("`") != -1:
                table_name = content[content.find("`") + 1:content.rfind("`")]
                if table_name not in sql_structure.keys():
                    sql_structure[table_name] = list()
        elif content.lower().startswith("`"):
            if find_table and table_name is not None:
                if content.find("`") != -1 and content[content.find("`") + 1:].find("`") != -1:
                    field = content[content.find("`") + 1:content[content.find("`") + 1:].find("`") + content.find("`") + 1]
                    sql_structure[table_name].append(field)
        elif content.lower().startswith("primary key") or content.lower().startswith(")"):
            find_table = False
            table_name = None

def scan_repo_sql(repo_path, sql_structure: dict):
    # 扫描整个代码仓库,获得完整的SQL结构
    for parent, dirnames, filenames in os.walk(repo_path):
        for filename in filenames:
            if filename.endswith(".sql") or filename.endswith(".php") or filename.endswith(".java") or filename.endswith(".c") or filename.endswith(".py"):
                file_path = os.path.join(parent, filename)
                try:
                    parse_sql(file_path, sql_structure)
                except:
                    pass

if __name__ == "__main__":
    repo_path = "/home/devdata/repos/remoteclinic_remoteclinic"
    sql_structure = {}
    scan_repo_sql(repo_path, sql_structure)
    for table_name in sql_structure.keys():
        print(f"{table_name}: {str(sql_structure[table_name])}")