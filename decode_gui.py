import tkinter as tk
from tkinter import filedialog, messagebox
from steganography import Steganography


def browse_image():
    path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    image_entry.delete(0, tk.END)
    image_entry.insert(0, path)


def decode_message():
    image_path = image_entry.get()
    password = password_entry.get() or None

    if not image_path:
        messagebox.showerror("Error", "Please select an image.")
        return

    try:
        steg = Steganography()
        message = steg.decode_image(image_path, password)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, message)
    except Exception as e:
        messagebox.showerror("Error", str(e))


root = tk.Tk()
root.title("Decode Message from Image")

tk.Label(root, text="Select Image:").grid(row=0, column=0, pady=5)
image_entry = tk.Entry(root, width=50)
image_entry.grid(row=0, column=1, pady=5)
tk.Button(root, text="Browse", command=browse_image).grid(row=0, column=2, padx=5)

tk.Label(root, text="Password (if needed):").grid(row=1, column=0, pady=5)
password_entry = tk.Entry(root, width=50, show="*")
password_entry.grid(row=1, column=1, pady=5, columnspan=2)

tk.Label(root, text="Decoded Message:").grid(row=2, column=0, pady=5)
output_text = tk.Text(root, width=38, height=5)
output_text.grid(row=2, column=1, pady=5, columnspan=2)

tk.Button(root, text="Decode", command=decode_message).grid(row=3, column=1, pady=15)

root.mainloop()
