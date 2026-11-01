# Author - Dor levek
# Date   - 12/2/25
# Function

import os
import shutil
import subprocess
import glob
import logging
import pyautogui
import protocol_utils as protocol

SCREENSHOT_FILENAME = "screenshot.jpg"
TEMP_DIR = "server_temp"


def handle_dir(params: list, _sock, cipher):
    """Handles the DIR command to list files."""
    path_or_pattern = params[0] if params and params[0] else os.getcwd()
    logging.info(f"Handling DIR command for: {path_or_pattern}")

    is_dir_no_wildcards = os.path.isdir(path_or_pattern) and not any(
        char in path_or_pattern for char in ['*', '?'])

    if is_dir_no_wildcards:
        search_pattern = os.path.join(path_or_pattern, "*")
    else:
        search_pattern = path_or_pattern

    try:
        full_path_list = glob.glob(search_pattern, recursive=False)
        content = []

        for item_path in full_path_list:
            item_name = os.path.basename(item_path)
            if os.path.isdir(item_path) and not item_name.endswith('/'):
                display_name = item_name + '/'
            else:
                display_name = item_name
            content.append(display_name)

        if not content:
            if os.path.exists(path_or_pattern):
                return 'OK', 'TEXT', f"No matches found for: {search_pattern}"
            else:
                return 'ERROR', 'TEXT', f"Path does not exist: {path_or_pattern}"

        return 'OK', 'LIST', content

    except Exception as err:
        logging.error(f"DIR Exception: {err}")
        return 'ERROR', 'TEXT', f"Error accessing directory: {err}"


def handle_delete(params: list, _sock, cipher):
    if not params or not params[0]:
        return 'ERROR', 'TEXT', 'Missing file path.'

    file_path = params[0]
    try:
        os.remove(file_path)
        return 'OK', 'TEXT', f"File {file_path} deleted successfully."
    except Exception as err:
        return 'ERROR', 'TEXT', f"Error deleting file: {err}"


def handle_copy(params: list, _sock, cipher):
    if len(params) < 2:
        return 'ERROR', 'TEXT', 'Missing source or destination path.'

    src, dst = params[0], params[1]
    try:
        shutil.copy2(src, dst)
        return 'OK', 'TEXT', f"File copied from {src} to {dst}."
    except Exception as err:
        return 'ERROR', 'TEXT', f"Error copying file: {err}"


def handle_execute(params: list, _sock, cipher):
    if not params or not params[0]:
        return 'ERROR', 'TEXT', 'Missing program path.'

    program_path = params[0]
    try:
        subprocess.Popen(program_path)
        return 'OK', 'TEXT', f"Program {program_path} launched successfully."
    except Exception as err:
        return 'ERROR', 'TEXT', f"Error executing program: {err}"


def handle_screenshot(_params, _sock, cipher):
    try:
        image = pyautogui.screenshot()
        os.makedirs(TEMP_DIR, exist_ok=True)
        image.save(os.path.join(TEMP_DIR, SCREENSHOT_FILENAME))
        return 'OK', 'TEXT', f"Screenshot saved in {TEMP_DIR}."
    except Exception as err:
        return 'ERROR', 'TEXT', f"Error taking screenshot: {err}"


def handle_send_photo(_params, sock, cipher):
    file_path = os.path.join(TEMP_DIR, SCREENSHOT_FILENAME)

    if not os.path.exists(file_path):
        msg = protocol.create_response_message(
            'ERROR', 'TEXT', 'Screenshot not found. Run SCREENSHOT first.'
        )
        protocol.send_message(sock, msg, cipher)
        return 'COMPLETED_RESPONSE', 'TEXT', 'N/A'

    try:
        with open(file_path, 'rb') as file_obj:
            file_bytes = file_obj.read()

        encrypted_file_bytes = cipher.encrypt(file_bytes)
        file_size = len(encrypted_file_bytes)

        # Send SIZE message encrypted
        size_msg = protocol.create_response_message('FILE', 'SIZE', str(file_size))
        protocol.send_message(sock, size_msg, cipher)

        # Send encrypted raw file data with protocol prefix (un-encrypted prefix wrapper)
        raw_payload_str = encrypted_file_bytes.decode(protocol.ENCODING)
        protocol.send_message(sock, raw_payload_str, cipher=None)

        final_msg = protocol.create_response_message(
            'OK', 'TEXT', f"File {SCREENSHOT_FILENAME} sent successfully."
        )
        protocol.send_message(sock, final_msg, cipher)

        return 'COMPLETED_RESPONSE', 'TEXT', 'N/A'

    except Exception as err:
        err_msg = protocol.create_response_message('ERROR', 'TEXT', f"Error: {err}")
        protocol.send_message(sock, err_msg, cipher)
        return 'COMPLETED_RESPONSE', 'TEXT', 'N/A'


def handle_exit(_params, _sock, cipher):
    return 'OK', 'TEXT', 'Connection closing.'