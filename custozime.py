import hashlib
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Union
import time
import secrets
import glob

def ask_user_for_message():
    """
    Asks the user if they want to use a message and performs actions accordingly.
    """
    use_message = input("Do you want to use a message? (default: y) [y/n]: ").strip().upper()

    if use_message == 'Y' or use_message == '':
        file_path = get_existing_file_path()
        pin = get_six_digit_pin()

        if os.path.exists("./frontend/custom/salt"):
            generate_salt()
        else:
            generateSaltFile()

        remove_other_files("./frontend/custom/salt")

        hashed_filename = sha256(pin)
        pin_to_key = pin_to_aes_key(pin)

        with open("./frontend/custom/timestamp", "w") as file:
            file.write(str(timestamp))

        encrypt_file_aes256(file_path, "./frontend/custom/" + hashed_filename, pin_to_key)
    elif use_message == 'N':
        print("No message will be used.")
        remove_other_files("./frontend/custom/timestamp")
    else:
        print("Invalid input. Please enter Y or N.")
        ask_user_for_message()

def generateSaltFile():
    """
    Generates a new salt and saves it to a file.
    """
    new_salt = secrets.token_hex(16)
    with open('./frontend/custom/salt', 'w') as f:
        f.write(new_salt)
    print("New salt generated and saved to './frontend/custom/salt'")

def generate_salt():
    """
    Prompts the user to generate a new salt and calls `generateSaltFile` accordingly.
    """
    generate_new_salt = input("Do you want to generate a new salt? (default: y) [y/n]: ").lower()
    if generate_new_salt == '' or generate_new_salt == 'y':
        generateSaltFile()
    elif generate_new_salt == 'n':
        print("No new salt generated.")
    else:
        print("Invalid input. Please enter 'y' or 'n'.")

def remove_other_files(file_to_keep):
    """
    Removes all other files in the directory except the specified file.
    """
    directory = os.path.dirname(file_to_keep)
    files = os.listdir(directory)
    files.remove(os.path.basename(file_to_keep))
    for file in files:
        file_path = os.path.join(directory, file)
        os.remove(file_path)

def get_timestamp():
    """
    Gets the timestamp either from the file or from user input.
    """
    timestamp_path = 'frontend/custom/timestamp'
    if os.path.isfile(timestamp_path):
        timestampExist = True
        with open(timestamp_path, 'r') as plik:
            timestamp_from_file = plik.read()
        prompt = f"Enter 10-digit timestamp (press Enter for {timestamp_from_file}):"
    else:
        timestampExist = False
        prompt = "Enter 10-digit timestamp:"

    while True:
        timestamp_str = input(prompt)
        if timestamp_str.strip() == "" and timestampExist:
            return timestamp_from_file
        elif len(timestamp_str) != 10:
            print("Invalid timestamp format. Timestamp should have exactly 10 digits.")
            continue
        try:
            timestamp = int(timestamp_str)
            if timestamp >= 0 and timestamp <= int(time.time()) + 10*365*24*3600:  # 10 years in seconds
                return timestamp
            else:
                print("Invalid timestamp. Please enter a valid timestamp.")
        except ValueError:
            print("Invalid input. Please enter a valid integer timestamp.")

def pin_to_aes_key(pin: Union[str, int]) -> bytes:
    """
    Converts PIN to AES key.
    """
    if not isinstance(pin, str) or not pin.isdigit() or len(pin) != 6:
        raise ValueError('PIN must contain 6 digits.')

    padded_pin = pin.ljust(8, '0')
    pin_bytes = padded_pin.encode()
    aes_key = bytearray(32)

    for i in range(0, 32, len(pin_bytes)):
        aes_key[i:i+len(pin_bytes)] = pin_bytes

    return bytes(aes_key)

def encrypt_file_aes256(input_file, output_file, key):
    """
    Encrypts a file using AES256.
    """
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)

def sha256(message):
    """
    Calculates SHA256 hash of a message concatenated with salt.
    """
    with open('./frontend/custom/salt', 'r') as file:
        salt = file.read().strip()
    message_with_salt = salt + message;
    message_bytes = message_with_salt.encode('utf-8')
    sha256_hash = hashlib.sha256(message_bytes).hexdigest()
    return sha256_hash

def get_six_digit_pin():
    """
    Gets a 6-digit PIN from the user.
    """
    while True:
        pin = input("Enter your 6-digit PIN for content encryption: ")
        if pin.isdigit() and len(pin) == 6:
            return pin
        else:
            print("Invalid input. PIN must be a 6-digit number.")

def get_existing_file_path():
    """
    Gets the path of an existing file from the user.
    """
    html_files = glob.glob("*.html")
    if html_files:
        prompt = f"Enter file path (press Enter for {html_files[0]}): "
    else:
        prompt = "Enter file path: "

    while True:
        file_path = input(prompt)
        if file_path == '' and html_files:
            file_path = html_files[0]
            return file_path
        elif os.path.exists(file_path):
            return file_path
        else:
            print("File does not exist. Please enter a valid file path.")

timestamp = get_timestamp()
ask_user_for_message()
