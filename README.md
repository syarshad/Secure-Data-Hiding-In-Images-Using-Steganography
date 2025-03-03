# Image Steganography with Encryption
A Python-based steganography tool for hiding and extracting secret messages within images.
## Overview
This project implements a secure image steganography system that hides secret messages inside images while encrypting them for double-layer protection. The hidden message is first encrypted using AES encryption (Fernet) and then embedded into the image using Least Significant Bit (LSB) steganography. This ensures that even if the hidden data is extracted, it cannot be read without the correct password.
## Project Structure
**1. **steganography.py:**** The core module containing the Steganography class with all encryption, encoding, and decoding functionality. item1
  
**2. **encode_gui.py:**** A standalone program for encoding messages into images with a dedicated GUI.
  
**3. **decode_gui.py:**** A standalone program for extracting hidden messages from images with its own GUI.
  
**4. **main.py:**** A menu interface that allows users to choose between encoding and decoding, launching the appropriate program.
## Dependencies
- Python 3.6+
- Pillow (PIL Fork)
- NumPy
- cryptography (for password protection)
- Tkinter (usually included with Python)

## Installation
### 1. Clone the Repository
### 2. Install the Dependencies
Make sure you have Python 3 installed. Then, install the required packages:
```
pip install pillow numpy cryptography
```
### 3. Run the GUI Applications
To Encode a Message:
```
python encode_gui.py
```

To Decode a Message:
```
python decode_gui.py
```
To open a menu that lets you choose between encoding and decoding:
```
python main.py
```

## Project Features
**1.  **Modular Design:**** Each component has a specific responsibility

**2.  **Password Protection:**** Optional encryption for secure message hiding

**3.  **User-Friendly GUI:**** Clean interfaces for both encoding and decoding

**4.  **Error Handling:**** Comprehensive validation and error messages

**5.  **Standalone Components:**** Encode and decode can work independently

