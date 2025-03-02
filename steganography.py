import cv2
import base64
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Steganography:
    def __init__(self):
        self.delimiter = "#####"
        self.salt = b'steganography_salt'

    def text_to_binary(self, text):
        return ''.join(format(ord(char), '08b') for char in text)

    def binary_to_text(self, binary):
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

    def encrypt_message(self, message, password):
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        f = Fernet(key)
        return f.encrypt(message.encode()).decode('utf-8')

    def decrypt_message(self, encrypted_message, password):
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        f = Fernet(key)
        return f.decrypt(encrypted_message.encode()).decode('utf-8')

    def encode_image(self, image_path, message, output_path, password=None):
        if password:
            message = self.encrypt_message(message, password)
        message += self.delimiter

        img = cv2.imread(image_path)
        if img is None:
            raise Exception("Could not read the image.")

        binary_message = self.text_to_binary(message)
        if len(binary_message) > img.size:
            raise Exception("Message too large to encode in image.")

        flat_img = img.flatten().astype(int)
        for i in range(len(binary_message)):
            flat_img[i] = (flat_img[i] & ~1) | int(binary_message[i])

        flat_img = np.clip(flat_img, 0, 255)
        encoded_img = flat_img.reshape(img.shape).astype(np.uint8)
        cv2.imwrite(output_path, encoded_img)

    def decode_image(self, image_path, password=None):
        img = cv2.imread(image_path)
        if img is None:
            raise Exception("Could not read the image.")

        flat_img = img.flatten()
        binary_data = ""
        for byte in flat_img:
            binary_data += str(byte & 1)
            if len(binary_data) >= 8 * len(self.delimiter):
                if self.delimiter in self.binary_to_text(binary_data[-8 * len(self.delimiter):]):
                    break

        extracted_text = self.binary_to_text(binary_data).split(self.delimiter)[0]
        if password:
            extracted_text = self.decrypt_message(extracted_text, password)

        return extracted_text
