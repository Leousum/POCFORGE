import asyncio
import re

import requests
import websockets


class CPGQLSTransport:

    def __init__(self):
        self._ws_conn = None

    def connect(self, endpoint):
        self._ws_conn = websockets.connect(endpoint, ping_interval=None)
        return self._ws_conn

    async def recv(self):
        await self._ws_conn.recv()

    def post(self, uri, **kwargs):
        return requests.post(uri, **kwargs)

    def get(self, uri, **kwargs):
        return requests.get(uri, **kwargs)


class CPGQLSClient:
    CPGQLS_MSG_CONNECTED = "connected"
    DEFAULT_TIMEOUT = 3600

    def __init__(self, server_endpoint, event_loop=None, transport=None, auth_credentials=None):
        if server_endpoint is None:
            raise ValueError("server_endpoint cannot be None")
        if not isinstance(server_endpoint, str):
            raise ValueError("server_endpoint parameter has to be a string")

        self._loop = asyncio.get_event_loop() if not event_loop else event_loop
        self._transport = CPGQLSTransport() if not transport else transport
        self._endpoint = server_endpoint.rstrip("/")
        self._auth_creds = auth_credentials

    def execute(self, query, timeout=DEFAULT_TIMEOUT):
        return self._loop.run_until_complete(self._send_query(query, timeout=timeout))

    async def _send_query(self, query, timeout=DEFAULT_TIMEOUT):
        endpoint = self.connect_endpoint()
        async with self._transport.connect(endpoint) as ws_conn:
            connected_msg = await ws_conn.recv()
            if connected_msg != self.CPGQLS_MSG_CONNECTED:
                exception_msg = """Received unexpected first message
                on websocket endpoint"""
                raise Exception(exception_msg)
            endpoint = self.post_query_endpoint()
            post_res = self._transport.post(endpoint, json={"query": query}, auth=self._auth_creds)
            if post_res.status_code == 401:
                exception_msg = """Basic authentication failed"""
                raise Exception(exception_msg)
            elif post_res.status_code != 200:
                exception_msg = """Could not post query to the HTTP
                endpoint of the server"""
                raise Exception(exception_msg)
            await asyncio.wait_for(ws_conn.recv(), timeout=timeout)
            endpoint = self.get_result_endpoint(post_res.json()["uuid"])
            get_res = self._transport.get(endpoint, auth=self._auth_creds)
            if post_res.status_code == 401:
                exception_msg = """Basic authentication failed"""
                raise Exception(exception_msg)
            elif get_res.status_code != 200:
                exception_msg = """Could not retrieve query result via the HTTP endpoint
                of the server"""
                raise Exception(exception_msg)
            return get_res.json()

    def connect_endpoint(self):
        return "ws://" + self._endpoint + "/connect"

    def post_query_endpoint(self):
        return "http://" + self._endpoint + "/query"

    def get_result_endpoint(self, uuid):
        return "http://" + self._endpoint + "/result/" + uuid


def clean_stdout_output(stdout):
    """
    清理方法 stdout 中的控制字符，并解析出方法名、签名和全限定名。
    """
    # 使用正则表达式移除颜色控制字符
    clean_output = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', stdout)

    # 提取方法信息，假设格式为 ("methodName", "signature", "fullName")
    # method_pattern = re.compile(r'\(\s*"(?P<name>.*?)"\s*,\s*"(?P<signature>.*?)"\s*,\s*"(?P<fullname>.*?)"\s*\)')
    method_pattern = re.compile(
        r'\(\s*"(?P<name>[^"]+)",\s*"(?P<signature>[^"]+)",\s*"(?P<fullname>[^"]+)",\s*Some\(value\s*=\s*(?P<line_number>\d+)\s*\)'
    ) # re.compile(r'\(\s*"(?P<name>.*?)"\s*,\s*"(?P<signature>.*?)"\s*,\s*"(?P<fullname>.*?)"\s*,\s*"(?P<line_number>.*?)"\s*\)')
    methods = []

    for match in method_pattern.finditer(clean_output):
        method_name = match.group("name")
        signature = match.group("signature")
        full_name = match.group("fullname")
        line_number = match.group('line_number') if match.group('line_number') else None

        methods.append({
            "name": method_name,
            "signature": signature,
            "full_name": full_name,
            "line_number": int(line_number)
        })

    return methods