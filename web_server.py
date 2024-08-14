from enum import Enum
import socket
import os
from email.utils import formatdate
import datetime
import base64
import threading

test_account = {('test', 'test')}


def decode_basic_auth(auth_header):
    # If auth_header starts with "basic", such as 'Basic dXNlcm5hbWU6cGFzc3dvcmQ='
    if not auth_header.startswith('Basic '): raise ValueError(
        "Invalid authorization header")
    # Remove 'Basic ' phrase
    encoded_credentials = auth_header[6:]
    # Base64 decoding
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
    # Separate username and password
    username, password = decoded_credentials.split(':', 1)
    return username, password


class HttpResponse(Enum):
    OK = (200, "OK")
    NOT_MODIFIED = (304, "Not Modified")
    BAD_REQUEST = (400, "Bad Request")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")

    def __init__(self, code, phrase):
        self.code = code
        self.phrase = phrase

    def response(self, html_content="", extra_headers=""):
        date_header = f"date: {formatdate(timeval=None, localtime=False, usegmt=True)}"
        connection_header = "connection: keep-alive"
        headers = f"{date_header}\n{connection_header}\n{extra_headers}"
        if self.code == 200 and html_content:
            return f"HTTP/1.1 {self.code} {self.phrase}\ncontent-type: text/html\n{headers}\n\n{html_content}"
        return f"HTTP/1.1 {self.code} {self.phrase}\n{headers}\n"

def read(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            last_modified = os.path.getmtime(file_path)
            return content, last_modified
    else:
        return None, None

def parse_http_first_line(request):
    # Split request lines
    request_parts = request.split(' ')
    method = request_parts[0]  # Request method
    full_path = request_parts[1]  # Request path with parameters

    # Obtain path and parameters
    path_and_params = full_path.split('?')
    path = path_and_params[0]  # Path
    params = {}  # Parameters
    if len(path_and_params) > 1:
        # Process parameters
        params_str = path_and_params[1]
        param_pairs = params_str.split('&')
        for pair in param_pairs:
            key_value = pair.split('=')
            key = key_value[0]
            value = key_value[1] if len(key_value) > 1 else None
            params[key] = value

    return method, path, params


def parse_http_headers(header):
    header_fields = {}
    for element in header:
        pairs = element.split(':')
        if len(pairs) >= 2:
            header_fields[pairs[0].strip().lower()] = ':'.join(pairs[1:]).strip()
    return header_fields


def check_auth(auth):
    username, password = decode_basic_auth(auth)
    if (username, password) in test_account:
        return True
    else:
        return False


def check_bad_request(method, params):
    # Support GET only
    if method != 'GET':
        return True
    if len(params) != 0:
        return True


def check_not_modified(header_dict, last_modified):
    if 'if-modified-since' in header_dict:
        if datetime.datetime.strptime(header_dict['if-modified-since'], '%a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=datetime.timezone.utc).timestamp() >= last_modified:
            print(f"if-modified-since: {datetime.datetime.strptime(header_dict['if-modified-since'], '%a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=datetime.timezone.utc).timestamp()} >= last_modified: {last_modified}")
            return True
    return False


def handle_request(request):
    header = request.split('\n')
    method, path, params = parse_http_first_line(header[0])
    path = path[1:]
    print(method, path, params)
    header_dict = parse_http_headers(header)

    if check_bad_request(method, params) is True:
        return HttpResponse.BAD_REQUEST.response()
    if path == 'auth.html':
        if 'authorization' in header_dict:
            Auth = header_dict['authorization']
            if check_auth(Auth) is False:
                return HttpResponse.FORBIDDEN.response()
        else:
            return HttpResponse.FORBIDDEN.response()

    # check if file exist
    if os.path.exists(path):
        content, last_modified = read(path)
        last_modified = int(last_modified)
        if check_not_modified(header_dict, last_modified):
            return HttpResponse.NOT_MODIFIED.response()
        extra_headers = "last-modified: {}".format(datetime.datetime.fromtimestamp(last_modified, datetime.UTC).strftime('%a, %d %b %Y %H:%M:%S GMT'))
        return HttpResponse.OK.response(content, extra_headers)
    else:
        return HttpResponse.NOT_FOUND.response()


def handle_client(client_socket, addr):
    print(f"Web: connection from {addr}")
    request = client_socket.recv(1024).decode()
    if len(request) == 0:
        return
    response = handle_request(request)
    print(response)
    client_socket.sendall(response.encode())
    # Close the connection
    client_socket.close()


def main():
    SERVER_HOST = '0.0.0.0'
    PORT = 8088
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a public host and a port
    server_socket.bind((SERVER_HOST, PORT))

    # Set the server to listen mode, with a max queue of 1 connection
    server_socket.listen(1)

    print("Web Server is listening...")
    # localhost=127.0.0.1=ip
    # 1. Sever Run
    # 2. client ip:port->msg
    # 3. response=handle_request(msg)
    # 4. Sever ->response
    while True:
        # Establish a connection
        client_socket, addr = server_socket.accept()
        # main process
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()
main()
