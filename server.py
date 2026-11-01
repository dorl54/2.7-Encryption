# Author - Dor levek
# Date   - 12/2/25
# Server

import socket
import threading
import os
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
import function as handlers
import protocol_utils as protocol

SERVER_IP = '0.0.0.0'
PORT = 12345
TEMP_DIR = "server_temp"

COMMAND_HANDLERS = {
    'DIR': handlers.handle_dir,
    'DELETE': handlers.handle_delete,
    'COPY': handlers.handle_copy,
    'EXECUTE': handlers.handle_execute,
    'SCREENSHOT': handlers.handle_screenshot,
    'SEND_PHOTO': handlers.handle_send_photo,
    'EXIT': handlers.handle_exit
}


def recv_exact(sock, length):
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet: return None
        data += packet
    return data


def handle_client(client_socket: socket.socket):
    try:
        addr = client_socket.getpeername()
        print(f"--- New client connected from {addr} ---")
        logging.info(f"New connection from {addr}")

        # 1. Generate RSA key pair
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.publickey().export_key()

        # 2. Send RSA Public Key to client
        client_socket.sendall(len(public_key).to_bytes(4, 'big'))
        client_socket.sendall(public_key)

        # 3. Receive encrypted Fernet symmetric key from client
        fernet_key_len_bytes = recv_exact(client_socket, 4)
        if not fernet_key_len_bytes: return
        fernet_key_len = int.from_bytes(fernet_key_len_bytes, 'big')
        encrypted_fernet_key = recv_exact(client_socket, fernet_key_len)

        # 4. Decrypt Fernet key using server private key
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        fernet_key = cipher_rsa.decrypt(encrypted_fernet_key)
        cipher = Fernet(fernet_key)
        print("Secure channel established.")

        while True:
            raw_message = protocol.receive_message(client_socket, cipher)
            if not raw_message:
                logging.info(f"Client {addr} disconnected.")
                break

            parsed_data = protocol.parse_message(raw_message)
            command = parsed_data['command'].upper()
            params = parsed_data['params']

            if command in COMMAND_HANDLERS:
                status, dtype, data = COMMAND_HANDLERS[command](params, client_socket, cipher)
            else:
                status, dtype, data = 'ERROR', 'TEXT', f"Unknown command: {command}"

            if status != 'COMPLETED_RESPONSE':
                response = protocol.create_response_message(status, dtype, data)
                protocol.send_message(client_socket, response, cipher)

            if command == 'EXIT':
                break

    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        client_socket.close()
        logging.info("Client socket closed.")


def setup_server(ip: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((ip, port))
    sock.listen(5)
    return sock


def accept_connections(server_socket: socket.socket):
    print(f"Server listening at {SERVER_IP}:{PORT}")
    logging.info(f"Server started on {SERVER_IP}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()


def main():
    os.makedirs(TEMP_DIR, exist_ok=True)
    server_socket = None
    try:
        server_socket = setup_server(SERVER_IP, PORT)
        accept_connections(server_socket)
    except Exception as e:
        print(f"Server fatal error: {e}")
        logging.critical(f"Server crashed: {e}")
    finally:
        if server_socket:
            server_socket.close()


if __name__ == "__main__":
    logging.basicConfig(filename='server.log', level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    main()