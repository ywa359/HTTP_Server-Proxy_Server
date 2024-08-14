import socket
import os
from email.utils import formatdate
import h2.events
import h2.config
import h2.connection
import base64
import datetime
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

def read(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            last_modified = os.path.getmtime(file_path)
            return content, last_modified
    else:
        return None, None

def check_auth(auth):
    username, password = decode_basic_auth(auth)
    if (username, password) in test_account:
        return True
    else:
        return False


def check_bad_request(event, path):
    # Support GET only
    headers = event.headers
    for name, value in headers:
        if name == b':method':
            if value.decode('utf-8') != 'GET':
                return True
    # Obtain parameters and mark as bad request if there are any
    params = path.split('?')
    if len(params) > 1:
        return True


def check_not_modified(event, last_modified):
    headers = event.headers
    for name, value in headers:
        if name.lower() == b'if-modified-since':
            if datetime.datetime.strptime(value.decode('utf-8'), '%a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=datetime.timezone.utc).timestamp() >= last_modified:
                print(f"if-modified-since: {datetime.datetime.strptime(value.decode('utf-8'), '%a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=datetime.timezone.utc).timestamp()} >= last_modified: {last_modified}")
                return True
            break
    return False

def send_response(conn, stream_id, status, content=None, last_modified=None):
    headers=[
        (':status', status),
        ('date', formatdate(timeval=None, localtime=False, usegmt=True)),
        ('content-type', 'text/html'),
    ]

    # If status code is 200 and last_modified is provided, add the Last-Modified header
    if status == '200' and last_modified is not None:
        headers.append(('last-modified', datetime.datetime.fromtimestamp(last_modified, datetime.UTC).strftime('%a, %d %b %Y %H:%M:%S GMT')))
    
    conn.send_headers(stream_id=stream_id, headers=headers)
    
    if content is not None:
        conn.send_data(stream_id=stream_id, data=content.encode('utf-8'), end_stream=True)
    else:
        conn.end_stream(stream_id)

def handle_request(conn, event):
    stream_id = event.stream_id
    path = None
    for name, value in event.headers:
        if name == b':path':
            path = value.decode('utf-8').lstrip('/')
            break
    if check_bad_request(event, path) is True:
        send_response(conn, stream_id, '400')
        return
    if path == 'auth.html':
        hasAuthHeader = False
        for name, value in event.headers:
            if name.lower() == b'authorization':
                auth = value.decode('utf-8')
                if check_auth(auth) is False:
                    send_response(conn, stream_id, '403')
                    return
                hasAuthHeader = True
        if (hasAuthHeader is False):
            send_response(conn, stream_id, '403')
            return

    # check if file exist
    if os.path.exists(path):
        content, last_modified = read(path)
        last_modified = int(last_modified)
        if check_not_modified(event, last_modified):
            send_response(conn, stream_id, '304')
            return
        send_response(conn, stream_id, '200', content, last_modified)
    else:
        send_response(conn, stream_id, '404')
    
def handle(sock, addr):
    print(f"HTTP/2 Web Server: connection from {addr}")
    config = h2.config.H2Configuration(client_side=False)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    while True:
        data = sock.recv(65535)
        if not data:
            break
        
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                handle_request(conn, event)

        data_to_send = conn.data_to_send()
        if data_to_send:
            print(f"Sending response to {addr}")
            sock.sendall(data_to_send)


def main():
    SERVER_HOST = '0.0.0.0'
    PORT = 8088
    
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to a public host and a port
    server_socket.bind((SERVER_HOST, PORT))

    # Set the server to listen mode, with a max queue of 5 connections
    server_socket.listen(5)

    print("HTTP/2 Web Server is listening...")
    # localhost=127.0.0.1=ip
    # 1. Sever Run
    # 2. client ip:port->msg
    # 3. response=handle_request(msg)
    # 4. Sever ->response
    while True:
        # main process
        conn, addr = server_socket.accept()
        threading.Thread(handle(conn, addr)).start()
main()
