import cv2
import numpy as np
from PIL import Image
import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Steganography:
    def __init__(self):
        self.delimiter = "#####"  # Delimiter to separate message from noise
    
    def text_to_binary(self, text):
        """Convert text to binary representation"""
        binary = ''.join(format(ord(char), '08b') for char in text)
        return binary
    
    def binary_to_text(self, binary):
        """Convert binary back to text"""
        binary_values = [binary[i:i+8] for i in range(0, len(binary), 8)]
        text = ''.join(chr(int(binary_val, 2)) for binary_val in binary_values)
        return text
    
    def encrypt_message(self, message, password):
        """Encrypt message using password"""
        # Convert password to key
        password_bytes = password.encode()
        salt = b'steganography_salt'  # A fixed salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        # Encrypt message
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return encrypted_message.decode('utf-8')
    
    def decrypt_message(self, encrypted_message, password):
        """Decrypt message using password"""
        # Convert password to key
        password_bytes = password.encode()
        salt = b'steganography_salt'  # Same fixed salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        # Decrypt message
        f = Fernet(key)
        try:
            decrypted_message = f.decrypt(encrypted_message.encode())
            return decrypted_message.decode('utf-8')
        except Exception as e:
            raise ValueError("Invalid password or corrupted message")
    
    def encode(self, image_path, message, output_path, password=None):
        """Hide a message in an image"""
        # Encrypt the message if password is provided
        if password:
            message = self.encrypt_message(message, password)
        
        # Add delimiter to know where message ends
        message += self.delimiter
        
        # Read the image
        img = cv2.imread(image_path)
        
        # Check if image was loaded properly
        if img is None:
            raise Exception("Could not read the image.")
        
        # Convert message to binary
        binary_message = self.text_to_binary(message)
        message_length = len(binary_message)
        
        # Check if the image is big enough to hold the message
        max_bytes = img.shape[0] * img.shape[1] * 3 // 8
        if message_length > max_bytes:
            raise Exception(f"Message too large. The image can only store {max_bytes} bits.")
        
        # Flatten the image to 1D array
        img_flat = img.flatten()
        
        # Embed the binary message into the least significant bits of the image
        data_index = 0
        for i in range(message_length):
            # Get the corresponding bit from the message
            bit = int(binary_message[i])
            
            # Replace the least significant bit of the pixel value
            # with the message bit
            img_flat[data_index] = (img_flat[data_index] & 0xFE) | bit
            data_index += 1
        
        # Reshape the flattened array back to the original image shape
        img_with_message = img_flat.reshape(img.shape)
        
        # Save the image with the hidden message
        cv2.imwrite(output_path, img_with_message)
        return f"Message hidden successfully. Output saved to {output_path}"
    
    def decode(self, image_path, password=None):
        """Extract a hidden message from an image"""
        # Read the image
        img = cv2.imread(image_path)
        
        # Check if image was loaded properly
        if img is None:
            raise Exception("Could not read the image.")
        
        # Flatten the image to 1D array
        img_flat = img.flatten()
        
        # Extract the message bits
        binary_message = ""
        for i in range(len(img_flat)):
            if len(binary_message) % 8 == 0 and len(binary_message) > 0:
                # Check if we've reached the delimiter
                current_bytes = binary_message[-8 * len(self.delimiter):]
                if len(current_bytes) >= 8 * len(self.delimiter):
                    possible_delimiter = self.binary_to_text(current_bytes)
                    if possible_delimiter.endswith(self.delimiter):
                        break
            
            # Extract the least significant bit
            binary_message += str(img_flat[i] & 1)
        
        # Convert the binary message back to text
        extracted_text = self.binary_to_text(binary_message)
        
        # Remove the delimiter
        if self.delimiter in extracted_text:
            extracted_text = extracted_text.split(self.delimiter)[0]
        
        # Decrypt the message if password is provided
        if password:
            try:
                extracted_text = self.decrypt_message(extracted_text, password)
            except ValueError as e:
                raise ValueError("Incorrect password or message is not encrypted")
        
        return extracted_text


# Create a test image if none exists
def create_test_image(filename, size=(300, 300)):
    # Create a new RGB image with a gradient
    img = np.zeros((size[0], size[1], 3), dtype=np.uint8)
    # Fill with a simple gradient
    for i in range(size[0]):
        for j in range(size[1]):
            img[i, j] = [(i*255)//size[0], (j*255)//size[1], 100]
    
    # Save the image
    im = Image.fromarray(img)
    im.save(filename)
    print(f"Created test image: {filename}")
    return filename


class SteganographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("550x450")
        self.root.configure(padx=20, pady=20)
        
        self.steg = Steganography()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.encode_frame = ttk.Frame(self.notebook)
        self.decode_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.encode_frame, text="Encode")
        self.notebook.add(self.decode_frame, text="Decode")
        
        # Style configuration
        style = ttk.Style()
        style.configure('TButton', font=('Arial', 10))
        style.configure('TLabel', font=('Arial', 10))
        style.configure('TEntry', font=('Arial', 10))
        
        # Create Encode tab widgets
        self.setup_encode_tab()
        
        # Create Decode tab widgets
        self.setup_decode_tab()
    
    def setup_encode_tab(self):
        # Encode Frame Widgets
        ttk.Label(self.encode_frame, text="Select Original Image:").grid(row=0, column=0, sticky='w', pady=5)
        
        self.encode_image_path = tk.StringVar()
        ttk.Entry(self.encode_frame, textvariable=self.encode_image_path, width=40).grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(self.encode_frame, text="Browse", command=self.browse_encode_image).grid(row=0, column=2, pady=5)
        
        ttk.Label(self.encode_frame, text="Message to Hide:").grid(row=1, column=0, sticky='w', pady=5)
        
        self.message_text = tk.Text(self.encode_frame, width=40, height=5)
        self.message_text.grid(row=1, column=1, columnspan=2, pady=5, padx=5)
        
        ttk.Label(self.encode_frame, text="Password (Optional):").grid(row=2, column=0, sticky='w', pady=5)
        
        self.encode_password = tk.StringVar()
        ttk.Entry(self.encode_frame, textvariable=self.encode_password, show="*", width=40).grid(row=2, column=1, pady=5, padx=5)
        
        ttk.Label(self.encode_frame, text="Save Output Image as:").grid(row=3, column=0, sticky='w', pady=5)
        
        self.output_path = tk.StringVar()
        ttk.Entry(self.encode_frame, textvariable=self.output_path, width=40).grid(row=3, column=1, pady=5, padx=5)
        ttk.Button(self.encode_frame, text="Browse", command=self.browse_output_path).grid(row=3, column=2, pady=5)
        
        # Status label
        self.encode_status = tk.StringVar()
        ttk.Label(self.encode_frame, textvariable=self.encode_status, wraplength=400).grid(row=5, column=0, columnspan=3, pady=10)
        
        # Encode button
        ttk.Button(self.encode_frame, text="Encode Message", command=self.encode_message).grid(row=4, column=1, pady=20)
    
    def setup_decode_tab(self):
        # Decode Frame Widgets
        ttk.Label(self.decode_frame, text="Select Image with Hidden Message:").grid(row=0, column=0, sticky='w', pady=5)
        
        self.decode_image_path = tk.StringVar()
        ttk.Entry(self.decode_frame, textvariable=self.decode_image_path, width=40).grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(self.decode_frame, text="Browse", command=self.browse_decode_image).grid(row=0, column=2, pady=5)
        
        ttk.Label(self.decode_frame, text="Password (if needed):").grid(row=1, column=0, sticky='w', pady=5)
        
        self.decode_password = tk.StringVar()
        ttk.Entry(self.decode_frame, textvariable=self.decode_password, show="*", width=40).grid(row=1, column=1, pady=5, padx=5)
        
        ttk.Label(self.decode_frame, text="Extracted Message:").grid(row=2, column=0, sticky='w', pady=5)
        
        self.decoded_message = tk.Text(self.decode_frame, width=40, height=8)
        self.decoded_message.grid(row=2, column=1, columnspan=2, pady=5, padx=5)
        
        # Status label
        self.decode_status = tk.StringVar()
        ttk.Label(self.decode_frame, textvariable=self.decode_status, wraplength=400).grid(row=4, column=0, columnspan=3, pady=10)
        
        # Decode button
        ttk.Button(self.decode_frame, text="Decode Message", command=self.decode_message).grid(row=3, column=1, pady=20)
    
    def browse_encode_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if file_path:
            self.encode_image_path.set(file_path)
            # Set default output path
            if not self.output_path.get():
                dir_name = os.path.dirname(file_path)
                base_name = os.path.basename(file_path)
                name, ext = os.path.splitext(base_name)
                self.output_path.set(os.path.join(dir_name, f"{name}_encoded{ext}"))
    
    def browse_output_path(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".png", 
                                                 filetypes=[("PNG files", "*.png"), 
                                                           ("All files", "*.*")])
        if file_path:
            self.output_path.set(file_path)
    
    def browse_decode_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if file_path:
            self.decode_image_path.set(file_path)
    
    def encode_message(self):
        try:
            # Get inputs
            image_path = self.encode_image_path.get()
            message = self.message_text.get("1.0", "end-1c")
            password = self.encode_password.get()
            output_path = self.output_path.get()
            
            # Validate inputs
            if not image_path:
                self.encode_status.set("Please select an input image.")
                return
            
            if not message:
                self.encode_status.set("Please enter a message to hide.")
                return
            
            if not output_path:
                self.encode_status.set("Please select an output path.")
                return
            
            # Encode the message
            result = self.steg.encode(
                image_path, 
                message, 
                output_path, 
                password if password else None
            )
            
            self.encode_status.set(result)
            messagebox.showinfo("Success", "Message hidden successfully!")
            
        except Exception as e:
            self.encode_status.set(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))
    
    def decode_message(self):
        try:
            # Get inputs
            image_path = self.decode_image_path.get()
            password = self.decode_password.get()
            
            # Validate input
            if not image_path:
                self.decode_status.set("Please select an image.")
                return
            
            # Decode the message
            extracted_message = self.steg.decode(
                image_path, 
                password if password else None
            )
            
            # Display the message
            self.decoded_message.delete("1.0", tk.END)
            self.decoded_message.insert("1.0", extracted_message)
            self.decode_status.set("Message extracted successfully!")
            
        except Exception as e:
            self.decode_status.set(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))


# Main entry point
if __name__ == "__main__":
    # Create test image if needed
    if not os.path.exists("original_image.png"):
        create_test_image("original_image.png")
    
    # Create and run the GUI
    root = tk.Tk()
    app = SteganographyGUI(root)
    root.mainloop()