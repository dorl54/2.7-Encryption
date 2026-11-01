# Author - Dor levek
# Date   - 12/2/25
# Client

import socket
import logging
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
import protocol_utils as protocol

SERVER_IP = '127.0.0.1'
PORT = 12345
DEFAULT_FILE_NAME = "default_received_screenshot.jpg"


def recv_exact(sock, length):
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet: return None
        data += packet
    return data


def display_response(raw_response: str):
    try:
        parsed_response = protocol.parse_message(raw_response)
        status = parsed_response['command']
        data_type = parsed_response['type']
        data = parsed_response['params']

        print("-" * 30)
        print(f"Status: {status} | Data Type: {data_type}")

        if status == 'ERROR':
            print(f" Server Error: {data[0]}")
        elif data_type == 'LIST':
            print(" Directory Content:")
            for item in data:
                print(f"  - {item}")
        elif data_type == 'TEXT':
            print(f"Message: {data[0]}")

    except Exception as e:
        print(f" Error decoding: {e}")
        logging.error(f"Decoding error: {e}")


def handle_file_transfer(sock: socket.socket, file_size: int, dest_path: str, cipher):
    """Receives encrypted binary payload using protocol prefixing and decrypts it."""
    print(f"Receiving {file_size} bytes...")
    logging.info(f"Downloading file to {dest_path}")

    # Use the protocol to receive the encrypted raw bytes safely
    encrypted_payload_str = protocol.receive_message(sock)
    if not encrypted_payload_str:
        logging.error("Connection lost during transfer")
        return False

    try:
        encrypted_bytes = encrypted_payload_str.encode(protocol.ENCODING)
        file_content = cipher.decrypt(encrypted_bytes)

        os.makedirs(os.path.dirname(dest_path) or '.', exist_ok=True)
        with open(dest_path, 'wb') as f:
            f.write(file_content)
        print(f" File saved: {dest_path}")
        return True
    except Exception as e:
        logging.error(f"File save/decrypt error: {e}")
        return False


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, PORT))
        print(f" Successfully connected to server at {SERVER_IP}:{PORT}")
        logging.info("Connected to server")

        # 1. Receive Public Key from Server
        pub_key_len_bytes = recv_exact(client_socket, 4)
        pub_key_len = int.from_bytes(pub_key_len_bytes, 'big')
        public_key_bytes = recv_exact(client_socket, pub_key_len)

        # 2. Generate Symmetric Fernet Key
        fernet_key = Fernet.generate_key()
        cipher = Fernet(fernet_key)

        # 3. Encrypt Fernet Key using Server's RSA Public Key and Send
        pub_key_obj = RSA.import_key(public_key_bytes)
        cipher_rsa = PKCS1_OAEP.new(pub_key_obj)
        encrypted_fernet_key = cipher_rsa.encrypt(fernet_key)

        client_socket.sendall(len(encrypted_fernet_key).to_bytes(4, 'big'))
        client_socket.sendall(encrypted_fernet_key)
        print("Secure channel established.")

        print("\nExample Commands:")
        print("EXECUTE C:\\Windows\\System32\\notepad.exe")
        print("EXECUTE C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
        print("COPY C:\\a.txt/C:\\b.txt")
        print("DIR C:\\Users\\public\\")
        print("DELETE C:\\temp\\file.txt")
        print("SCREENSHOT")
        print("SEND_PHOTO C:\\temp\\my_new_screenshot.jpg")
        print("EXIT")

        while True:
            user_input = input("\n (COMMAND PARAM1/PARAM2): ").strip()
            if not user_input:
                continue

            parts = user_input.split(' ', 1)
            command = parts[0].upper()
            params = parts[1].split(protocol.PARAM_SEPARATOR) if len(parts) > 1 else []

            msg = protocol.create_command_message(command, params)
            protocol.send_message(client_socket, msg, cipher)

            raw_resp = protocol.receive_message(client_socket, cipher)
            if not raw_resp:
                print("Server closed the connection.")
                break

            if 'FILE' in raw_resp:
                dest = params[0] if (command == 'SEND_PHOTO' and params) else DEFAULT_FILE_NAME
                file_info = protocol.parse_message(raw_resp)
                size = int(file_info['params'][0])

                handle_file_transfer(client_socket, size, dest, cipher)
                raw_resp = protocol.receive_message(client_socket, cipher)
                if not raw_resp:
                    break

            display_response(raw_resp)

            if command == 'EXIT':
                break

    except ConnectionRefusedError:
        print(f" Connection failed. Ensure the server is running at {SERVER_IP}:{PORT}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        client_socket.close()
        logging.info("Socket closed")


if __name__ == "__main__":
    logging.basicConfig(filename='client.log', level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    main()