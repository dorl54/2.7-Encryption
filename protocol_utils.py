# Author - Dor levek
# Date   - 12/2/25
# Protocol

import time
import socket
import logging

# Protocol Constants
LENGTH_FIELD_SIZE = 8
DELIMITER = "#@"
PARAM_SEPARATOR = "/"
ENCODING = 'utf-8'


def send_message(sock: socket.socket, raw_data: str, cipher=None) -> bool:
    """Encodes and sends a message with a fixed-length prefix. Encrypts if cipher is provided."""
    try:
        encoded_data = raw_data.encode(ENCODING)

        if cipher:
            encoded_data = cipher.encrypt(encoded_data)

        data_length = len(encoded_data)
        length_prefix = str(data_length).zfill(LENGTH_FIELD_SIZE)
        full_message = length_prefix.encode(ENCODING) + encoded_data

        sock.sendall(full_message)
        logging.debug(f"Message sent: {raw_data}")
        return True
    except Exception as e:
        logging.error(f"Failed to send message: {e}")
        return False


def receive_message(sock: socket.socket, cipher=None) -> str | None:
    """Receives a message by reading the length prefix first in a strict loop."""
    try:
        prefix_bytes = b''
        while len(prefix_bytes) < LENGTH_FIELD_SIZE:
            chunk = sock.recv(LENGTH_FIELD_SIZE - len(prefix_bytes))
            if not chunk:
                return None
            prefix_bytes += chunk

        length_prefix = prefix_bytes.decode(ENCODING)
        expected_length = int(length_prefix)

        chunks = []
        bytes_recd = 0
        while bytes_recd < expected_length:
            chunk = sock.recv(expected_length - bytes_recd)
            if not chunk:
                return None
            chunks.append(chunk)
            bytes_recd += len(chunk)

        raw_data_bytes = b"".join(chunks)

        if cipher:
            raw_data_bytes = cipher.decrypt(raw_data_bytes)

        raw_data = raw_data_bytes.decode(ENCODING)
        logging.debug(f"Message received: {raw_data}")
        return raw_data

    except Exception as e:
        logging.error(f"Error receiving message: {e}")
        return None


def parse_message(message: str) -> dict:
    try:
        parts = message.split(DELIMITER, 2)
        return {
            'command': parts[0],
            'type': parts[1],
            'params': parts[2].split(PARAM_SEPARATOR)
        }
    except Exception as e:
        logging.error(f"Error parsing message: {e}")
        return {'command': 'ERROR', 'type': 'TEXT', 'params': ['Invalid protocol format.']}


def create_command_message(command: str, params: list) -> str:
    timestamp = str(int(time.time()))
    data_string = PARAM_SEPARATOR.join(params)
    return f"{command}{DELIMITER}{timestamp}{DELIMITER}{data_string}"


def create_response_message(status: str, data_type: str, data: str | list) -> str:
    if isinstance(data, list):
        data_string = PARAM_SEPARATOR.join(data)
    else:
        data_string = str(data)
    return f"{status}{DELIMITER}{data_type}{DELIMITER}{data_string}"