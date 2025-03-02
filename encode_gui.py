import tkinter as tk
from tkinter import filedialog, messagebox
from steganography import Steganography


def browse_input_image():
    path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    input_entry.delete(0, tk.END)
    input_entry.insert(0, path)


def browse_output_image():
    path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    output_entry.delete(0, tk.END)
    output_entry.insert(0, path)


def encode_message():
    image_path = input_entry.get()
    output_path = output_entry.get()
    message = message_text.get("1.0", tk.END).strip()
    password = password_entry.get() or None

    if not image_path or not output_path or not message:
        messagebox.showerror("Error", "Please fill all fields.")
        return

    try:
        steg = Steganography()
        steg.encode_image(image_path, message, output_path, password)
        messagebox.showinfo("Success", "Message encoded successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))


root = tk.Tk()
root.title("Encode Message into Image")

tk.Label(root, text="Select Image:").grid(row=0, column=0, pady=5)
input_entry = tk.Entry(root, width=50)
input_entry.grid(row=0, column=1, pady=5)
tk.Button(root, text="Browse", command=browse_input_image).grid(row=0, column=2, padx=5)

tk.Label(root, text="Output Image:").grid(row=1, column=0, pady=5)
output_entry = tk.Entry(root, width=50)
output_entry.grid(row=1, column=1, pady=5)
tk.Button(root, text="Browse", command=browse_output_image).grid(row=1, column=2, padx=5)

tk.Label(root, text="Message:").grid(row=2, column=0, pady=5)
message_text = tk.Text(root, width=38, height=5)
message_text.grid(row=2, column=1, pady=5, columnspan=2)

tk.Label(root, text="Password (optional):").grid(row=3, column=0, pady=5)
password_entry = tk.Entry(root, width=50, show="*")
password_entry.grid(row=3, column=1, pady=5, columnspan=2)

tk.Button(root, text="Encode", command=encode_message).grid(row=4, column=1, pady=15)

root.mainloop()
