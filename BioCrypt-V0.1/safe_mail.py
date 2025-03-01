import os
import json
import smtplib
import mimetypes
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from email.message import EmailMessage
import hashlib
import secrets
import string
from io import BytesIO

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import csv

CSV_FILE = "data/theme_settings.csv"


def read_from_csv():
  
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            row = next(reader)
            return row[0], row[1]  
    except FileNotFoundError:
        return "#ffffff", "#000000"  


bg_color, fg_color = read_from_csv()
var1 = {"bg": bg_color}
var2 = {"fg": fg_color}


FONT_MAIN = ("Courier", 14)
FONT_ENTRY = ("Courier", 12)
FONT_HEADER = ("Courier", 20, "bold")


SENDER_EMAIL = "biocryptprogram@gmail.com"
SENDER_PASSWORD = ""

JSON_MAPPING_FILE = "data/decryption_keys.json"


def generate_decryption_key():

    characters = string.ascii_letters + string.digits
    rand_str = ''.join(secrets.choice(characters) for _ in range(31))
    return rand_str[:14] + "-" + rand_str[14:]


def generate_code():

    return ''.join(secrets.choice(string.digits) for _ in range(6))


def update_json_mapping(code, decryption_key):

    data = {}
    if os.path.exists(JSON_MAPPING_FILE):
        try:
            with open(JSON_MAPPING_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}
    data[code] = decryption_key
    with open(JSON_MAPPING_FILE, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Updated JSON mapping: {code} -> {decryption_key}")


def encrypt_file_in_memory(input_path, decryption_key):

    aes_key = hashlib.sha256(decryption_key.encode()).digest()[:16]
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypted_data = iv + ciphertext
    return encrypted_data


def decrypt_file(input_path, decryption_key):

    aes_key = hashlib.sha256(decryption_key.encode()).digest()[:16]
    with open(input_path, "rb") as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(plaintext_padded, AES.block_size)
    except ValueError:
        raise ValueError("Incorrect decryption key or corrupted file.")
    output_path = input_path + ".dec"
    with open(output_path, "wb") as f:
        f.write(plaintext)
    return output_path


def send_email_with_attachment_data(encrypted_data, original_filename, recipient_email, code):

    subject = "Your Encrypted File and Retrieval Code"
    body = (
        "Hello,\n\n"
        "Please find attached the encrypted file.\n\n"
        "Use the following code to retrieve the decryption key from our secure system:\n"
        f"{code}\n\n"
        "Best regards,\n"
    )
    msg = EmailMessage()
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.set_content(body)

    ctype, encoding = mimetypes.guess_type(original_filename)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"
    maintype, subtype = ctype.split("/", 1)
    attachment_filename = os.path.basename(original_filename) + ".enc"
    msg.add_attachment(encrypted_data, maintype=maintype,
                       subtype=subtype, filename=attachment_filename)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Error sending email:\n{e}")
        return False

#GUI

root = tk.Tk()
root.title("Safe Mail Application")
root.configure(bg=var1["bg"])
root.geometry("600x500")


header_frame = tk.Frame(root, bg=var1["bg"])
header_frame.pack(pady=10)
header_label = tk.Label(header_frame, text="Safe Mail Application", font=(
    "Courier", 24, "bold"), bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
header_label.pack()

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=20, pady=10)

# ---------------------
# Tab 1: Send File
# ---------------------
tab_send = tk.Frame(notebook, bg=var1["bg"])
notebook.add(tab_send, text="Send File")
for i in range(3):
    tab_send.columnconfigure(i, weight=1)


send_headline = tk.Label(tab_send, text="Send File",
                         font=FONT_HEADER, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
send_headline.grid(row=0, column=0, columnspan=3, pady=(10, 20))


send_recipient_label = tk.Label(
    tab_send, text="Recipient Email:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
send_recipient_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
send_recipient_entry = tk.Entry(tab_send, font=FONT_ENTRY)
send_recipient_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")


send_file_label = tk.Label(
    tab_send, text="File to Send:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"])
send_file_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")
send_file_entry = tk.Entry(tab_send, font=FONT_ENTRY)
send_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")


def browse_send_file():
    filename = filedialog.askopenfilename()
    if filename:
        send_file_entry.delete(0, tk.END)
        send_file_entry.insert(0, filename)


send_browse_button = tk.Button(
    tab_send, text="Browse", command=browse_send_file, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
send_browse_button.grid(row=2, column=2, padx=10, pady=10)


def send_file_action():
    recipient_email = send_recipient_entry.get().strip()
    file_path = send_file_entry.get().strip()
    if not recipient_email:
        messagebox.showwarning(
            "Input Error", "Please enter the recipient's email address.")
        return
    if not file_path or not os.path.exists(file_path):
        messagebox.showwarning(
            "Input Error", "Please select a valid file to send.")
        return
    
    decryption_key = generate_decryption_key()
    code = generate_code()
    update_json_mapping(code, decryption_key)
    
    encrypted_data = encrypt_file_in_memory(file_path, decryption_key)
    if send_email_with_attachment_data(encrypted_data, file_path, recipient_email, code):
        messagebox.showinfo(
            "Success", f"Email sent successfully!\nThe file was encrypted automatically.")
    else:
        messagebox.showerror("Failure", "Failed to send email.")


send_button = tk.Button(tab_send, text="Send Email",
                        command=send_file_action, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
send_button.grid(row=3, column=1, padx=10, pady=20)

# ---------------------
# Tab 2: Decrypt
# ---------------------
tab_decrypt = tk.Frame(notebook, bg=var1["bg"])
notebook.add(tab_decrypt, text="Decrypt")
for i in range(3):
    tab_decrypt.columnconfigure(i, weight=1)


decrypt_headline = tk.Label(
    tab_decrypt, text="Decrypt File", font=FONT_HEADER,  bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
decrypt_headline.grid(row=0, column=0, columnspan=3, pady=(10, 20))

decrypt_file_label = tk.Label(
    tab_decrypt, text="Encrypted File:", font=FONT_MAIN,  bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
decrypt_file_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
decrypt_file_entry = tk.Entry(tab_decrypt, font=FONT_ENTRY)
decrypt_file_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")


def browse_decrypt_file():
    filename = filedialog.askopenfilename(
        filetypes=[("Encrypted Files", "*.enc")])
    if filename:
        decrypt_file_entry.delete(0, tk.END)
        decrypt_file_entry.insert(0, filename)


decrypt_browse_button = tk.Button(
    tab_decrypt, text="Browse", command=browse_decrypt_file, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
decrypt_browse_button.grid(row=1, column=2, padx=10, pady=10)


decrypt_code_label = tk.Label(
    tab_decrypt, text="Code:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"])
decrypt_code_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")
decrypt_code_entry = tk.Entry(tab_decrypt, font=FONT_ENTRY)
decrypt_code_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")


def decrypt_file_action():
    encrypted_path = decrypt_file_entry.get().strip()
    code = decrypt_code_entry.get().strip()
    if not encrypted_path or not os.path.exists(encrypted_path):
        messagebox.showwarning(
            "Input Error", "Please select a valid encrypted file.")
        return
    if not code:
        messagebox.showwarning("Input Error", "Please enter the code.")
        return
    
    data = {}
    if os.path.exists(JSON_MAPPING_FILE):
        try:
            with open(JSON_MAPPING_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}
    if code not in data:
        messagebox.showerror(
            "Error", "Decryption key not found for the provided code.")
        return
    decryption_key = data[code]
    try:
        output_path = decrypt_file(encrypted_path, decryption_key)
        messagebox.showinfo(
            "Success", f"File decrypted successfully!\nSaved as: {output_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")


decrypt_button = tk.Button(
    tab_decrypt, text="Decrypt File", command=decrypt_file_action, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
decrypt_button.grid(row=3, column=1, padx=10, pady=20)

root.mainloop()
