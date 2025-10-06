import os

from utils.log_manager import LogManager

class Reporter(object):
    def __init__(self, log_manager: LogManager, report_root: str):
        self.log_manager = log_manager
        self.report_root = report_root
        self.html_escape_dict = { '&': '&amp;', '>': '&gt;', '<': '&lt;', '"': '&quot;', '\'': '&apos;' } # html escape chracters HTML转义字符
        if not os.path.exists(self.report_root):
            os.makedirs(self.report_root, mode = 0o777)

    def get_report_path(self, call_info: dict):
        # 获取报告的保存路径
        # if isinstance(call_info, dict) and "path" in call_info.keys():
        #     if call_info["path"]:
        #         return os.path.join(self.report_root, call_info["path"] + ".html")
        num = 1
        report_path = os.path.join(self.report_root, f"report_{str(num)}.html")
        while os.path.exists(report_path):
            num += 1
            report_path = os.path.join(self.report_root, f"report_{str(num)}.html")
        return report_path

    def _html_escape(self, string):
        # Escape HTML
        return ''.join(self.html_escape_dict.get(c,c) for c in string)

    def output_report(self, call_info: dict, vuln_type = None, func_name = None):
        # 输出报告
        self.log_manager.log_info('Generating a Report...', False, 1, True)
        output_path = self.get_report_path(call_info)
        if call_info["call_stack"] == [] or os.path.exists(output_path):
            return
        out = open(output_path, 'w')
        out.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability - Report</title>
    <style type="text/css">
    .container { padding: 3px 3px 3px 3px; font-size: 14px; }
    .odd_call { background-color: #CCCCCC; border: 2px solid #555555; margin: 0px 0px 5px 0px }
    .even_call { background-color: #DDDDDD; padding: 3px 3px 3px 3px; margin: 0px 0px 5px 0px }
    .filepath { font-size: small; font-weight: bold; color: #0000AA; padding: 5px 5px 5px 5px; }
    .codechunk { font-family: monospace; font-size: small; white-space: pre-wrap; padding: 0px 0px 0px 50px; }
    .linenumber { font-family: monospace; font-size: small; float: left; color: #777777; }
    </style>
    <script language="javascript">
        function togglePrev(node) {
            var targetDiv = node.previousSibling;
            targetDiv.style.display = (targetDiv.style.display=='none')?'block':'none';
            node.innerHTML = (node.innerHTML=='+ show +')?'- hide -':'+ show +';
        }
        function toggleNext(node) {
            var targetDiv = node.nextSibling;
            targetDiv.style.display = (targetDiv.style.display=='none')?'block':'none';
            node.innerHTML = (node.innerHTML=='+ show +')?'- hide -':'+ show +';
        }
    </script>
</head>
<body>
<div style="width: 100%; margin: 0px auto">""")
        out.write("""
    <b># <i>Here is a <font style="color:red">%s</font> vulnerability analysis report, and the sink function is <font style="color:red">%s()</font></i> </b> <br>""" % (vuln_type, func_name))
        out.write("""
    <b># <i>Taint data is: </i> <font style="color:red">%s</font></b>""" % self._html_escape(call_info["taint_data"]))
        for index in range(0, len(call_info["call_stack"])):
            item = call_info["call_stack"][index]
            if item["prev_line"] is None or item["start_line"] is None or item["end_line"] is None or item["next_line"] is None:
                continue
            out.write("""
    <div class="container">
        <br />""")
            # 根据奇偶给定模块class类型
            if index % 2 == 0:
                out.write("""
        <div class="even_call">""")
            else:
                out.write("""
        <div class="odd_call">""")
            # 输出前缀代码
            out.write("""
            <div class="filepath">%s</div>
            <div style="display: none">
                <div class="linenumber">""" % item["file_path"])
            for i in range(item["prev_line"], item["start_line"]):
                out.write("""
                %d<br />""" % (i))
            out.write("""
                </div>
                <div class="codechunk">%s</div>
            </div><a href="javascript:;" onclick="togglePrev(this);">+ show +</a>""" % self._html_escape('\n'.join(item["codes"][item["prev_line"]-item["prev_line"]:item["start_line"]-item["prev_line"]])))
            # 输出重要代码
            out.write("""
            <div>
                <div class="linenumber">""")
            for i in range(item["start_line"], item["end_line"] + 1):
                out.write("""
                %d<br />""" % (i))
            out.write("""
                </div>
                <div class="codechunk">%s</div>
            </div>""" % self._html_escape('\n'.join(item["codes"][item["start_line"] - item["prev_line"] : item["end_line"] - item["prev_line"] + 1])))
            # 输出后缀代码
            out.write("""
            <a href="javascript:;" onclick="toggleNext(this);">+ show +</a><div style="display: none">
                <div class="linenumber">""")
            for i in range(item["end_line"] + 1, item["next_line"]):
                out.write("""
                %d<br />""" % (i))
            out.write("""
                </div>
                <div class="codechunk">%s</div>
            </div>
        </div>""" % self._html_escape('\n'.join(item["codes"][item["end_line"] - item["prev_line"] + 1 : item["next_line"] - item["prev_line"] + 1])))
            out.write("""
    </div>""")
        out.write("""
</div>
</body>
</html>""")
        out.close()