def run():
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
    import sys
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    import csv

    # Define the function to handle paths inside and outside the app bundle

    def resource_path(relative_path):
        """ Get absolute path to resource (works in dev and PyInstaller bundled app). """
        if getattr(sys, 'frozen', False):  # Running in a PyInstaller bundle
            base_path = sys._MEIPASS
        else:
            base_path = os.path.abspath(".")  # Normal dev mode
        return os.path.join(base_path, relative_path)

    # Reference the CSV file using resource_path
    # Put your file inside a "data" folder
    CSV_FILE = resource_path('data/theme_settings.csv')

    def read_from_csv():
        """ Read data from CSV file. """
        try:
            with open(CSV_FILE, mode='r') as file:
                reader = csv.reader(file)
                row = next(reader)
                return row[0], row[1]
        except (FileNotFoundError, StopIteration):
            return "#ffffff", "#000000"  # Defaults if file not found or empty

    bg_color, fg_color = read_from_csv()
    var1 = {"bg": bg_color}
    var2 = {"fg": fg_color}

    FONT_MAIN = ("Courier", 14)
    FONT_ENTRY = ("Courier", 12)
    FONT_HEADER = ("Courier", 20, "bold")

    SENDER_EMAIL = ""
    SENDER_PASSWORD = ""

    def generate_code():
        """
        Generates a random 6-digit numeric code (as a string).
        Example: "346243"
        """
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    def generate_aes_key_from_code(random_code, secret_code):
        """
        Combines the random code and secret code, then hashes them to generate a 32-byte AES key.
        """
        combined_code = random_code + secret_code
        return hashlib.sha256(combined_code.encode()).digest()

    def encrypt_file_in_memory(input_path, random_code, secret_code):
        """
        Encrypts the file using AES in CBC mode.
        The random code and secret code are combined to generate the AES key.
        """
        aes_key = generate_aes_key_from_code(random_code, secret_code)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        with open(input_path, "rb") as f:
            plaintext = f.read()
        padded_plaintext = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        encrypted_data = iv + ciphertext
        return encrypted_data

    def decrypt_file(input_path, random_code, secret_code):
        """
        Decrypts the AES-encrypted file using the random code and secret code.
        """
        aes_key = generate_aes_key_from_code(random_code, secret_code)
        with open(input_path, "rb") as f:
            data = f.read()
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        try:
            plaintext = unpad(plaintext_padded, AES.block_size)
        except ValueError:
            raise ValueError("Incorrect code or corrupted file.")
        output_path = input_path[:-4]  # Remove .enc extension
        with open(output_path, "wb") as f:
            f.write(plaintext)
        return output_path

    def send_email_with_attachment_data(encrypted_data, original_filename, recipient_email, code):
        """
        Sends an email from the fixed sender to the recipient with the encrypted data (as bytes) attached.
        The email body contains the code so the recipient can decrypt the file.
        """
        subject = "Your Encrypted File and Decryption Code"
        body = (
            "Hello,\n\n"
            "Please find attached the encrypted file.\n\n"
            "Use the following code to decrypt the file:\n"
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

    ###########################################
    # Build the GUI
    ###########################################

    root = tk.Tk()
    root.title("Safe Mail Application")
    root.configure(bg=var2["fg"])
    root.geometry("600x500")
    root.resizable(False, False)
    # Global header
    header_frame = tk.Frame(root, bg=var2["fg"])
    header_frame.pack(pady=10)
    header_label = tk.Label(header_frame, text="Safe Mail", font=(
        "Courier", 50, "bold"), bg=var2["fg"], fg=var1["bg"], relief="flat", bd=0, highlightthickness=0)
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

    # Centered headline for Send File tab
    send_headline = tk.Label(tab_send, text="Send File",
                             font=FONT_HEADER, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
    send_headline.grid(row=0, column=0, columnspan=3, pady=(10, 20))

    # Recipient Email
    send_recipient_label = tk.Label(
        tab_send, text="Recipient Email:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
    send_recipient_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
    send_recipient_entry = tk.Entry(tab_send, font=FONT_ENTRY)
    send_recipient_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    # File to Send (plaintext file)
    # File to Send (plaintext file)
    send_file_label = tk.Label(
        tab_send, text="File to Send:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"])
    send_file_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")
    send_file_entry = tk.Entry(tab_send, font=FONT_ENTRY,
                               state="readonly")  # Set to readonly
    send_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

    def browse_send_file():
        filename = filedialog.askopenfilename()
        if filename:
            # Temporarily enable editing
            send_file_entry.config(state="normal")
            send_file_entry.delete(0, tk.END)
            send_file_entry.insert(0, filename)
            send_file_entry.config(state="readonly")  # Set back to readonly

    send_browse_button = tk.Button(
        tab_send, text="Browse", command=browse_send_file, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
    send_browse_button.grid(row=2, column=2, padx=10, pady=10)

    # Secret Code Dropdown
    secret_code_label = tk.Label(
        tab_send, text="Secret Code:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"])
    secret_code_label.grid(row=3, column=0, padx=10, pady=10, sticky="e")

    # Create a list of numbers from 000000 to 999999
    secret_code_values = [f"{i:06d}" for i in range(0, 1000000)]
    secret_code_combobox = ttk.Combobox(
        tab_send, values=secret_code_values, font=FONT_ENTRY, state="readonly")
    secret_code_combobox.grid(row=3, column=1, padx=10, pady=10, sticky="ew")
    secret_code_combobox.current(0)  # Set default value to 000000

    def send_file_action():
        recipient_email = send_recipient_entry.get().strip()
        file_path = send_file_entry.get().strip()
        secret_code = secret_code_combobox.get().strip()  # Get secret code from dropdown
        if not recipient_email:
            messagebox.showwarning(
                "Input Error", "Please enter the recipient's email address.")
            return
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning(
                "Input Error", "Please select a valid file to send.")
            return
        if not secret_code:
            messagebox.showwarning(
                "Input Error", "Please select a secret code.")
            return
        # Generate a 6-digit code
        random_code = generate_code()
        # Encrypt the file in memory
        encrypted_data = encrypt_file_in_memory(
            file_path, random_code, secret_code)
        if send_email_with_attachment_data(encrypted_data, file_path, recipient_email, random_code):
            messagebox.showinfo(
                "Success", f"Email sent successfully!")
        else:
            messagebox.showerror("Failure", "Failed to send email.")

    send_button = tk.Button(tab_send, text="Send Email",
                            command=send_file_action, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
    send_button.grid(row=4, column=1, padx=10, pady=20)

    # ---------------------
    # Tab 2: Decrypt
    # ---------------------
    tab_decrypt = tk.Frame(notebook, bg=var1["bg"])
    notebook.add(tab_decrypt, text="Decrypt")
    for i in range(3):
        tab_decrypt.columnconfigure(i, weight=1)

    # Centered headline for Decrypt tab
    decrypt_headline = tk.Label(
        tab_decrypt, text="Decrypt File", font=FONT_HEADER,  bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
    decrypt_headline.grid(row=0, column=0, columnspan=3, pady=(10, 20))

    # Encrypted File
    decrypt_file_label = tk.Label(
        tab_decrypt, text="Encrypted File:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"])
    decrypt_file_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
    decrypt_file_entry = tk.Entry(
        tab_decrypt, font=FONT_ENTRY, state="readonly")  # Set to readonly
    decrypt_file_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    def browse_decrypt_file():
        filename = filedialog.askopenfilename(
            filetypes=[("Encrypted Files", "*.enc")])
        if filename:
            # Temporarily enable editing
            decrypt_file_entry.config(state="normal")
            decrypt_file_entry.delete(0, tk.END)
            decrypt_file_entry.insert(0, filename)
            decrypt_file_entry.config(state="readonly")  # Set back to readonly

    # Secret Code for Decryption
    # Secret Code for Decryption
    decrypt_secret_code_label = tk.Label(
        tab_decrypt, text="Secret Code:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"])
    decrypt_secret_code_label.grid(
        row=3, column=0, padx=10, pady=10, sticky="e")

    # Create a list of numbers from 000000 to 999999
    secret_code_values = [f"{i:06d}" for i in range(0, 1000000)]
    decrypt_secret_code_combobox = ttk.Combobox(
        tab_decrypt, values=secret_code_values, font=FONT_ENTRY, state="readonly")
    decrypt_secret_code_combobox.grid(
        row=3, column=1, padx=10, pady=10, sticky="ew")
    decrypt_secret_code_combobox.current(0)  # Set default value to 000000
    decrypt_browse_button = tk.Button(
        tab_decrypt, text="Browse", command=browse_decrypt_file, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
    decrypt_browse_button.grid(row=1, column=2, padx=10, pady=10)

    # The user enters the code (to decrypt the file)
    decrypt_code_label = tk.Label(
        tab_decrypt, text="Code:", font=FONT_MAIN, bg=var1["bg"], fg=var2["fg"])
    decrypt_code_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")
    decrypt_code_entry = tk.Entry(tab_decrypt, font=FONT_ENTRY)
    decrypt_code_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

    def decrypt_file_action():
        encrypted_path = decrypt_file_entry.get().strip()
        random_code = decrypt_code_entry.get().strip()
        # Get secret code from combobox
        secret_code = decrypt_secret_code_combobox.get().strip()
        if not encrypted_path or not os.path.exists(encrypted_path):
            messagebox.showwarning(
                "Input Error", "Please select a valid encrypted file.")
            return
        if not random_code:
            messagebox.showwarning(
                "Input Error", "Please enter the random code.")
            return
        if not secret_code:
            messagebox.showwarning(
                "Input Error", "Please select a secret code.")
            return
        try:
            output_path = decrypt_file(
                encrypted_path, random_code, secret_code)
            messagebox.showinfo(
                "Success", f"File decrypted successfully!\nSaved as: {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    decrypt_button = tk.Button(
        tab_decrypt, text="Decrypt File", command=decrypt_file_action, font=FONT_ENTRY, bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0)
    decrypt_button.grid(row=4, column=1, padx=10, pady=20)

    root.mainloop()


if __name__ == "__main__":
    run()
