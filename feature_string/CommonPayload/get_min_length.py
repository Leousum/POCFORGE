import os
import json

num = 0
rootdir = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))
for parent, dirnames, filenames in os.walk(rootdir):
    for filename in filenames:
        path = os.path.join(parent, filename)
        if path.endswith(".json"):
            num += 1
            strings = []
            with open(path, "r", encoding = "utf-8") as f:
                strings = json.load(f)
            strings = sorted(strings, key = len)
            with open(path, "w", encoding = "utf-8") as f:
                json.dump(strings, f, ensure_ascii = False, indent = 4)
            # shortest_string = min(strings, key = len)
            shortest_string = "????????"
            min_length = 2
            if filename == "sql-injection-payload-list.json":
                min_length = 5
            for string in strings:
                if len(string) >= min_length and any(char.isalpha() for char in string) and string not in ["&lt;"]:
                    if len(string) <= len(shortest_string):
                        shortest_string = string
            print(f'({num}) {filename.split(".")[0].replace("-payload-list", "").replace("-", " ").capitalize()}')
            print(f"最短payload: {shortest_string}, 长度: {len(shortest_string)}")