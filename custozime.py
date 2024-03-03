import hashlib
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Union
import time
import secrets

def ask_user_for_message():
    use_message = input("Do you want to use a message? (Y/N): ").strip().upper()
    
    if use_message == 'Y':
        file_path = get_existing_file_path()
        pin = get_six_digit_pin()


        if os.path.exists("./frontend/custom/salt"):
            generate_salt()
        else:
            generateSaltFile()

        remove_other_files("./frontend/custom/salt")


        hashed_filename=sha256(pin)
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
        # Generate a new salt
    new_salt = secrets.token_hex(16)

    # Write the new salt to the file
    with open('./frontend/custom/salt', 'w') as f:
        f.write(new_salt)
    
    print("New salt generated and saved to './frontend/custom/salt'")

def generate_salt():
    # Ask the user if they want to generate a new salt
    generate_new_salt = input("Do you want to generate a new salt? (default: y) [y/n]: ").lower()

    # Default to generating a new salt if the user doesn't provide input
    if generate_new_salt == '' or generate_new_salt == 'y':
        generateSaltFile()
    elif generate_new_salt == 'n':
        print("No new salt generated.")
    else:
        print("Invalid input. Please enter 'y' or 'n'.")



def remove_other_files(file_to_keep):
    # Get the directory of the file to keep
    directory = os.path.dirname(file_to_keep)
    
    # Get a list of all files in the directory
    files = os.listdir(directory)
    
    # Remove the specified file from the list
    files.remove(os.path.basename(file_to_keep))
    
    # Remove all other files
    for file in files:
        file_path = os.path.join(directory, file)
        os.remove(file_path)
        #print(f"Removed: {file_path}")

def get_timestamp(prompt="Enter 10-digit timestamp:"):
    while True:
        timestamp_str = input(prompt)
        if len(timestamp_str) != 10:
            print("Invalid timestamp format. Timestamp should have exactly 10 digits.")
            continue
        try:
            timestamp = int(timestamp_str)
            # Check if the timestamp is within a reasonable range
            if timestamp >= 0 and timestamp <= int(time.time()) + 10*365*24*3600:  # 10 years in seconds
                return timestamp
            else:
                print("Invalid timestamp. Please enter a valid timestamp.")
        except ValueError:
            print("Invalid input. Please enter a valid integer timestamp.")

def pin_to_aes_key(pin: Union[str, int]) -> bytes:
    # Check if pin is a string and contains exactly 6 digits
    if not isinstance(pin, str) or not pin.isdigit() or len(pin) != 6:
        raise ValueError('PIN must contain 6 digits.')

    # Pad the PIN to 8 bytes with '0'
    padded_pin = pin.ljust(8, '0')

    # Encode the padded PIN to bytes
    pin_bytes = padded_pin.encode()

    # Initialize an AES key byte array
    aes_key = bytearray(32)

    # Set the AES key by repeating the PIN bytes
    for i in range(0, 32, len(pin_bytes)):
        aes_key[i:i+len(pin_bytes)] = pin_bytes

    return bytes(aes_key)

def encrypt_file_aes256(input_file, output_file, key):
    # Read the input file
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Generate an initialization vector (IV)
    iv = os.urandom(16)

    # Pad the plaintext to match the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Create an AES256 cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write the IV and ciphertext to the output file
    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)


def sha256(message):
    with open('./frontend/custom/salt', 'r') as file:
        salt = file.read().strip()  

    message_with_salt = salt + message;
    message_bytes = message_with_salt.encode('utf-8')
    sha256_hash = hashlib.sha256(message_bytes).hexdigest()
    return sha256_hash

def get_six_digit_pin():
    while True:
        pin = input("Enter your 6-digit PIN for content encryption: ")
        if pin.isdigit() and len(pin) == 6:
            return pin
        else:
            print("Invalid input. PIN must be a 6-digit number.")

def get_existing_file_path(prompt="Enter file path: "):
    while True:
        file_path = input(prompt)
        if os.path.exists(file_path):
            return file_path
        else:
            print("File does not exist. Please enter a valid file path.")


timestamp = get_timestamp()
ask_user_for_message()






