import os
import random
import smtplib
from tkinter import Tk, Label, Button, Listbox, Toplevel, Entry, filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import csv


CSV_FILE = "theme_settings.csv"  
def read_from_csv():
    # Read the theme settings from the CSV file
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            row = next(reader)
            return row[0], row[1]  # Return bg and fg values separately
    except FileNotFoundError:
        return "#ffffff", "#000000"  # Default values if CSV doesn't exist



bg_color, fg_color = read_from_csv()  
var1 = {"bg": bg_color}  
var2 = {"fg": fg_color}  




# Global variables
users = {}  # Stores user details: {email: [file_paths]}
otp_sent = None  # Stores the last OTP sent
file_owners = {}  # Maps files to their owner: {file_path: email}


# Fixed 256-bit key (32 bytes)
fixed_key = b"1234567890abcdef1234567890abcdef"  # Predefined key (you can change this to any 32-byte value)

# Encryption Function (with fixed key)
def encrypt_file(file_path, user_email):
    iv = os.urandom(16)  # 128-bit IV (initialization vector)

    # Read the file data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Pad the file data to be multiple of block size (AES block size is 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the data using AES in CBC mode with a fixed key
    cipher = Cipher(algorithms.AES(fixed_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted file to the 'vault' folder
    file_name = os.path.basename(file_path) + ".enc"  # Add .enc extension for encrypted files
    encrypted_file_path = os.path.join("vault", file_name)

    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + encrypted_data)  # Save IV + encrypted data

    # Save the file details to local storage
    with open("local_storage.txt", "a") as storage_file:
        storage_file.write(f"{encrypted_file_path} {user_email}\n")

    return encrypted_file_path


# Decrypt Function (with fixed key)
def decrypt_file(file_path, restore_folder):
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # Read the IV (first 16 bytes)
        encrypted_data = f.read()  # Read the rest as the encrypted data

    # Decrypt the data using AES in CBC mode with the fixed key
    cipher = Cipher(algorithms.AES(fixed_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data to get the original file content
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Save the restored (decrypted) file to the specified folder
    restored_file_path = os.path.join(restore_folder, os.path.basename(file_path).replace(".enc", ""))
    
    with open(restored_file_path, 'wb') as f:
        f.write(original_data)

    return restored_file_path

# Function to generate and send OTP via email
def send_otp(email):
    global otp_sent
    otp_sent = str(random.randint(100000, 999999))  # Generate OTP
    try:
        # Send OTP via email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("biocryptprogram@gmail.com", "nwxv ztza szsi trcx")  # Replace with actual credentials
            message = f"Subject: Vault OTP Verification\n\nYour OTP is: {otp_sent}"
            server.sendmail("your_email@gmail.com", email, message)
        
        messagebox.showinfo("OTP Sent", f"An OTP has been sent to {email}. Please enter it to confirm.")
    
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send OTP: {str(e)}")


# Function to verify OTP and decrypt the file
def verify_otp(action, file_path, email):
    def check_otp():
        entered_otp = otp_entry.get().strip()  # Get OTP entered by user
        if entered_otp == otp_sent:
            if action == "get":
                # Ask for destination folder to restore the file
                restore_folder = filedialog.askdirectory(title="Select Folder to Restore the File")
                if restore_folder:
                    # Decrypt the file and save it to the destination folder
                    restored_file_path = decrypt_file(file_path, restore_folder)
                    messagebox.showinfo("File Restored", f"File has been restored to {restore_folder}.")
                refresh_file_list()
            elif action == "delete":
                os.remove(file_path)  # Delete the file from the vault
                messagebox.showinfo("File Deleted", "The file has been successfully deleted.")
                refresh_file_list()
            otp_window.destroy()
        else:
            messagebox.showerror("Invalid OTP", "The OTP entered is incorrect.")

    # Create OTP input window
    otp_window = Toplevel(vault_app)
    otp_window.title("Enter OTP")
    otp_window.geometry("300x200")
    Label(otp_window, text="Enter OTP:", font=("Courier", 12)).pack(pady=10)
    otp_entry = Entry(otp_window, font=("Courier", 12))
    otp_entry.pack(pady=10)
    Button(otp_window, text="Submit", command=check_otp, font=("Courier", 12)).pack(pady=10)


# Function to refresh the file list display for the user
def refresh_file_list():
    file_listbox.delete(0, "end")
    if os.path.exists("vault"):
        for file_name in os.listdir("vault"):
            if file_name.endswith(".enc"):  # Show only encrypted files
                file_listbox.insert("end", file_name)


def file_action(action):
    selected_indices = file_listbox.curselection()
    
    if not selected_indices:
        messagebox.showerror("No File Selected", "Please select a file from the list before performing an action.")
        return

    selected_file = file_listbox.get(selected_indices)
    selected_filename = os.path.basename(selected_file).strip()  # Get the selected file's name with .enc
    file_found = False

    # Loop through lines in the local storage
    with open("local_storage.txt", "r") as file:
        for line in file:
            line = line.strip()  # Remove leading/trailing spaces

            # Skip empty lines
            if not line:
                continue

            # Debug: Print each line to check its format
            print(f"Line in storage: '{line}'")  # Add quotes to see if extra spaces exist

            # Split the line by spaces
            parts = line.split()

            # Ensure we have at least two parts: file path and email
            if len(parts) >= 2:
                # The last part should be the email, and the rest should be the file path
                email = parts[-1].strip()
                file_path = " ".join(parts[:-1]).strip()  # Combine everything except the last part as the file path
                
                stored_filename = os.path.basename(file_path).strip()  # Get the stored file path with .enc

                # Debug: Print out the parts
                print(f"File path: '{file_path}', Email: '{email}'")

                # Check if the selected file matches the stored file path
                if selected_filename == stored_filename:  # Compare full file path (including .enc)
                    file_found = True
                    send_otp(email)  # Send OTP to the user before proceeding with any action
                    verify_otp(action, file_path, email)  # Verify OTP before proceeding
                    break
            else:
                # Log invalid lines for debugging
                print(f"Skipping invalid line (not enough parts): {line}")

    if not file_found:
        messagebox.showerror("File Not Found", "The selected file was not found in the vault.")

# Function to handle file drops (drag-and-drop)
def add_file(event=None):
    if event:
        file_path = event.data.strip()
    else:
        # Open file dialog if event is None (button click)
        file_path = filedialog.askopenfilename(title="Select File to Add")
    
    if file_path:
        print(f"File selected: {file_path}")  # Debugging: print selected file path
        email_popup(file_path)


def email_popup(file_path):
    # Create a new popup window to input the email
    popup = Toplevel(vault_app)
    popup.title("Enter Email")
    popup.geometry("300x200")

    # Add label and entry for email input
    Label(popup, text="Enter Your Email:").pack(pady=10)
    email_entry = Entry(popup)
    email_entry.pack(pady=10)

    def send_otp_and_verify():
        email = email_entry.get().strip()  # Get the email entered by the user
        if not email:
            messagebox.showerror("Error", "Email is required.")
            return

        # Send OTP to the email
        send_otp(email)

        # Open OTP verification popup and pass email and file_path
        otp_popup(email, file_path)  # Pass email and file path for further use

        popup.destroy()  # Close the email input window

    # Submit button to send OTP and open OTP window
    Button(popup, text="Submit", command=send_otp_and_verify).pack(pady=10)


def otp_popup(user_email, file_path):
    # Create OTP input window for OTP verification
    otp_window = Toplevel(vault_app)
    otp_window.title("Enter OTP")
    otp_window.geometry("300x200")

    # Add label and entry for OTP input
    Label(otp_window, text="Enter OTP:", font=("Courier", 12)).pack(pady=10)
    otp_entry = Entry(otp_window, font=("Courier", 12))
    otp_entry.pack(pady=10)

    def verify_otp_and_encrypt():
        entered_otp = otp_entry.get().strip()  # Get OTP entered by user
        if entered_otp == otp_sent:  # Check if entered OTP matches sent OTP
            # Encrypt the file and send a confirmation email
            encrypted_file_path = encrypt_file(file_path, user_email)
            messagebox.showinfo("Success", f"File added and encrypted for {user_email}.")

            # Send confirmation email after successful encryption
            send_confirmation_email(user_email, encrypted_file_path)

            otp_window.destroy()  # Close OTP window
            refresh_file_list()  # Refresh file list to show the new file

        else:
            messagebox.showerror("Invalid OTP", "The OTP entered is incorrect.")

    # Submit button to verify OTP and proceed
    Button(otp_window, text="Submit", command=verify_otp_and_encrypt, font=("Courier", 12)).pack(pady=10)



def send_confirmation_email(user_email, encrypted_file_path):
    try:
        # Set up the email server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("biocryptprogram@gmail.com", "nwxv ztza szsi trcx")  # Replace with your credentials
            
            subject = "File Encryption Confirmation"
            body = f"Hello,\n\nYour file has been successfully encrypted and added to the vault.\n\nEncrypted file path: {encrypted_file_path}\n\nBest regards,\nVault Team"
            
            message = f"Subject: {subject}\n\n{body}"
            
            # Send the email
            server.sendmail("your_email@gmail.com", user_email, message)
        
        messagebox.showinfo("Confirmation Email Sent", "A confirmation email has been sent to the provided address.")
    
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send confirmation email: {str(e)}")










# GUI setup
vault_app = TkinterDnD.Tk()  # Initialize TkinterDnD for drag and drop
vault_app.title("Vault")
vault_app.geometry("600x500")
vault_app.resizable(False, False)
vault_app.config(bg=var1["bg"])
Label(vault_app, text="The Vault",bg=var1["bg"],fg=var2["fg"], font=("Courier", 55, "bold")).pack(pady=10)

file_listbox = Listbox(
    vault_app,
    font=("Courier", 12),
    width=90,
    height=20,
    fg=var1["bg"],  # Set the text color
    bg=var2["fg"]  # Set the background color
)
file_listbox.pack(pady=10)


Button(vault_app, text="   Retrive    ", command=lambda: file_action("get"),bg=var1["bg"],fg=var2["fg"],relief="flat",bd=0,highlightthickness=0, font=("Courier", 12)).pack(pady=3)
Button(vault_app, text="    Delete    ", command=lambda: file_action("delete"),bg=var1["bg"],fg=var2["fg"],relief="flat",bd=0,highlightthickness=0, font=("Courier", 12)).pack(pady=3)




# Register drag and drop functionality for files
vault_app.drop_target_register(DND_FILES)
vault_app.dnd_bind('<<Drop>>', add_file)

# Button to open file dialog and add files
Button(vault_app, text="     Add      ", command=add_file,bg=var1["bg"],fg=var2["fg"],relief="flat",bd=0,highlightthickness=0, font=("Courier", 12)).pack(pady=3)

# Load files on startup
refresh_file_list()

vault_app.mainloop()






