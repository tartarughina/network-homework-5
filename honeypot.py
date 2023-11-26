import argparse
import paramiko
import socket
import threading
import concurrent.futures
import time
import os
import re

class CustomSSH(paramiko.ServerInterface):
    def __init__(self, attempts) -> None:
        super().__init__()
        self.attempts = attempts

    def check_auth_password(self, username: str, password: str) -> int:
        if username not in self.attempts.keys():
            return paramiko.AUTH_FAILED
        
        self.attempts[username] += 1
        if self.attempts[username] > 5:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        
        return paramiko.AUTH_FAILED
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # Allow PTY allocation for any request
        return True
    
    def check_channel_shell_request(self, channel):
        # Allow shell access for any request
        return True
    
    def get_username(self) -> str:
        return self.username
    

# Get the command line arguments
def get_args():
    parser = argparse.ArgumentParser(description="Honeypot SSH")
    parser.add_argument(
        "-p", help="port to listen on", default=22
    )

    return parser.parse_args()

def give_shell_access(channel, username):
    channel.send(f"{username}@honeypot:/$ ")

    last_interaction_time = time.time()
    command_buffer = ''  # Buffer to store the incoming command

    while True:
        if time.time() - last_interaction_time > 60:  # 60 seconds timeout
            channel.send("\n\rSession timed out due to inactivity.\n\r")
            break

        if channel.recv_ready():
            last_interaction_time = time.time()
            char = channel.recv(1).decode('utf-8')  # Read one character at a time
            if char == '\r' or char == '\n':  # Check for carriage return or newline
                channel.send("\r\n")
                command = command_buffer.strip()
                command_buffer = ''  # Reset the command buffer

                # Process the complete command
                if command == "exit": 
                    break
                
                response = process_command(command)

                channel.send(response)
                channel.send(f"\r{username}@honeypot:/$ ")
            elif char == '\x7f':  # Handle delete key (backspace)
                command_buffer = command_buffer[:-1]
                channel.send("\b \b")
            else:
                channel.send(char)
                command_buffer += char  # Accumulate characters

    channel.close()

def process_command(command):
    global fs

    if command == 'ls':
        return " ".join(fs.keys()) + "\n"
    elif command.startswith("echo "):
        pattern = r"echo\s+\"(.*?)\"\s+>\s+(\S+)"

        match = re.search(pattern, command)
        if match:
            content = match.group(1)
            file = match.group(2)

            if file.endswith(".txt"):
                fs[file] = content
            else:
                return "Unknown file extension\n"

            return ""
        else:
            return "Parse error\n"
    elif command.startswith("cat "):
        pattern = r"cat\s+(\S+)"

        match = re.search(pattern, command)
        if match:
            filename = match.group(1)
            if filename.endswith(".txt"):
                return fs.get(filename, f"File {filename} not found") + "\n"
            else:
                return "Unknown file extension\n"
        else:
            return "Cat error\n"
    elif command.startswith("cp "):
        pattern = r"cp\s+(\S+)\s+(\S+)"

        match = re.search(pattern, command)
        if match:
            source = match.group(1)
            destination = match.group(2)

            if source.endswith(".txt") and destination.endswith(".txt"):
                if source in fs:
                    fs[destination] = fs[source]
                    return ""
                else:
                    return f"File {source} not found\n"
            else:
                return "Unknown file extension\n"
        else:
            return "File not found\n"   
    else:
        return "Unknown command\n"

fs = {}  # Dictionary to store the file system
attempt_counts = {}  # Dictionary to keep track of login attempts
server_key = None

def handle_client(client_socket: socket):
    global attempt_counts

    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(server_key)

        server = CustomSSH(attempt_counts)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            raise Exception("Client did not open a channel.")

        # After 5 attempts, grant access
        give_shell_access(chan, server.get_username())

    except Exception as e:
        print(f"Exception: {e}")

    finally:
        transport.close()

def ssh_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', int(port)))
    server.listen(100)
    print(f"[*] Listening for connection on port {port}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        while True:
            client, addr = server.accept()

            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            executor.submit(handle_client, client)


def main():
    global server_key
    global attempt_counts

    args = get_args()

    if os.path.isfile("server.key"):
        server_key = paramiko.RSAKey(filename='server.key')
    else:
        server_key = paramiko.RSAKey.generate(2048)
        server_key.write_private_key_file('server.key')

    with open("usernames.txt") as f:
        for line in f.readlines():
            username = line.strip()
            attempt_counts[username] = 0
    
    ssh_server(args.p)

if __name__ == "__main__":
    main()