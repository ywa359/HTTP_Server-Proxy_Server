from enum import Enum
import socket
import os
from email.utils import formatdate
import threading
from datetime import datetime

support_account = {('test', 'test')}

class HttpResponse(Enum):
    OK = (200, "OK")
    NOT_MODIFIED = (304, "Not Modified")
    BAD_REQUEST = (400, "Bad Request")

    def __init__(self, code, phrase):
        self.code = code
        self.phrase = phrase

    def response(self, html_content="", extra_headers=""):
        date_header = f"Date: {formatdate(timeval=None, localtime=False, usegmt=True)}"
        connection_header = "Connection: keep-alive"
        headers = f"{date_header}\n{connection_header}\n{extra_headers}"
        if self.code == 200 and html_content:
            return f"HTTP/1.1 {self.code} {self.phrase}\nContent-Type: text/html\n{headers}\n\n{html_content}"
        return f"HTTP/1.1 {self.code} {self.phrase}\n{headers}\n"

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

def check_bad_request(method, params):
    # Support GET only
    if method != 'GET':
        return True
    if len(params) != 0:
        return True


def parse_http_headers(header):
    header_fields = {}
    for element in header:
        pairs = element.split(':')
        if len(pairs) == 2:
            header_fields[pairs[0].strip().lower()] = pairs[1].strip()
    return header_fields

def read(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            last_modified = os.path.getmtime(file_path)
            return content, last_modified
    else:
        return None, None
    
def check_not_modified(header_dict, last_modified):
    if 'if-modified-since' not in header_dict:
        return False
    if header_dict['if-modified-since'] == str(last_modified):
         return True
    
def forward_request_to_web_server(request):
    # Forward the request to the web server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8088))
    client_socket.sendall(request.encode())
    response = client_socket.recv(1024)

    if response.startswith(b'HTTP/1.1 200 OK'):
        print("Web server response: 200 OK. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    elif response.startswith(b'HTTP/1.1 304 Not Modified'):
        print("Web server response: 304 Not Modified. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    elif response.startswith(b'HTTP/1.1 400 Bad Request'):
        print("Web server response: 400 Bad Request. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    elif response.startswith(b'HTTP/1.1 403 Forbidden'):
        print("Web server response: 403 Forbidden. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    else:
        print("Web server response: 404 Not Found. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return response

def handle_request(request):
    header = request.split('\n')
    method, path, params = parse_http_first_line(header[0])
    path = path[1:]
    header_dict = parse_http_headers(header)
    # Handle bad request
    if check_bad_request(method, params) is True:
        print("Proxy server: 400 Bad Request. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        return HttpResponse.BAD_REQUEST.response()
    # check if file exists locally in proxy cache
    if os.path.exists(path) and path != 'auth.html':
        content, last_modified = read(path)
        if check_not_modified(header_dict, last_modified):
            print("Proxy server: 304 Not Modified. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return HttpResponse.NOT_MODIFIED.response()
        extra_headers = "last-modified: {}".format(last_modified)
        print("Proxy server: 200 OK. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        return HttpResponse.OK.response(content, extra_headers)
    else:
        print("Proxy server: File not found or file is auth.html, fetching from server. Date: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        return forward_request_to_web_server(request)


def handle_client(client_socket, addr):
    print(f"Proxy: Connection from {addr}")
    request = client_socket.recv(1024).decode()
    if len(request) == 0:
        return
    response = handle_request(request)
    if isinstance(response, str):
        response = response.encode()
    client_socket.send(response)
    # Close the connection
    client_socket.close()


def main():
    SERVER_HOST = '0.0.0.0'
    PORT = 8080
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a public host and a port
    server_socket.bind((SERVER_HOST, PORT))

    # Set the server to listen mode, with a max queue of 1 connection
    server_socket.listen(1)

    print("Proxy Server is listening...")
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
