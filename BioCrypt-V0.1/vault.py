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



users = {}  
otp_sent = None  
file_owners = {}  


fixed_key = b"BecaUKnowInAMomentItCouldAllPoow"




def encrypt_file(file_path, user_email):
    iv = os.urandom(16)  


    with open(file_path, 'rb') as f:
        file_data = f.read()

   
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()


    cipher = Cipher(algorithms.AES(fixed_key),
                    modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

 
    file_name = os.path.basename(file_path) + ".enc"
    encrypted_file_path = os.path.join("data/vault", file_name)

    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + encrypted_data)  


    with open("data/local_storage.txt", "a") as storage_file:
        storage_file.write(f"{encrypted_file_path} {user_email}\n")

    return encrypted_file_path



def decrypt_file(file_path, restore_folder):
    with open(file_path, 'rb') as f:
        iv = f.read(16)  
        encrypted_data = f.read() 

 
    cipher = Cipher(algorithms.AES(fixed_key),
                    modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()


    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

   
    restored_file_path = os.path.join(
        restore_folder, os.path.basename(file_path).replace(".enc", ""))

    with open(restored_file_path, 'wb') as f:
        f.write(original_data)

    return restored_file_path




def send_otp(email):
    global otp_sent
    otp_sent = str(random.randint(100000, 999999))  
    try:
        
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            
            server.login("biocryptprogram@gmail.com", "nwxv ztza szsi trcx")
            message = f"Subject: Vault OTP Verification\n\nYour OTP is: {otp_sent}"
            server.sendmail("your_email@gmail.com", email, message)

        messagebox.showinfo(
            "OTP Sent", f"An OTP has been sent to {email}. Please enter it to confirm.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to send OTP: {str(e)}")



def verify_otp(action, file_path, email):
    def check_otp():
        entered_otp = otp_entry.get().strip()  
        if entered_otp == otp_sent:
            if action == "get":
                
                restore_folder = filedialog.askdirectory(
                    title="Select Folder to Restore the File")
                if restore_folder:
                    
                    restored_file_path = decrypt_file(
                        file_path, restore_folder)
                    messagebox.showinfo(
                        "File Restored", f"File has been restored to {restore_folder}.")
                refresh_file_list()
            elif action == "delete":
                os.remove(file_path)  
                messagebox.showinfo(
                    "File Deleted", "The file has been successfully deleted.")
                refresh_file_list()
            otp_window.destroy()
        else:
            messagebox.showerror(
                "Invalid OTP", "The OTP entered is incorrect.")

  
    otp_window = Toplevel(vault_app)
    otp_window.title("Enter OTP")
    otp_window.geometry("300x200")
    Label(otp_window, text="Enter OTP:", font=("Courier", 12)).pack(pady=10)
    otp_entry = Entry(otp_window, font=("Courier", 12))
    otp_entry.pack(pady=10)
    Button(otp_window, text="Submit", command=check_otp,
           font=("Courier", 12)).pack(pady=10)



def refresh_file_list():
    file_listbox.delete(0, "end")
    if os.path.exists("data/vault"):
        for file_name in os.listdir("data/vault"):
            if file_name.endswith(".enc"):  
                file_listbox.insert("end", file_name)


def file_action(action):
    selected_indices = file_listbox.curselection()

    if not selected_indices:
        messagebox.showerror(
            "No File Selected", "Please select a file from the list before performing an action.")
        return

    selected_file = file_listbox.get(selected_indices)
    
    selected_filename = os.path.basename(selected_file).strip()
    file_found = False

    
    with open("data/local_storage.txt", "r") as file:
        for line in file:
            line = line.strip()  

            
            if not line:
                continue


            print(f"Line in storage: '{line}'")

            
            parts = line.split()

            
            if len(parts) >= 2:
               
                email = parts[-1].strip()
                
                file_path = " ".join(parts[:-1]).strip()

                
                stored_filename = os.path.basename(file_path).strip()

                
                print(f"File path: '{file_path}', Email: '{email}'")


                if selected_filename == stored_filename:
                    file_found = True
                    
                    send_otp(email)
                    
                    verify_otp(action, file_path, email)
                    break
            else:
                
                print(f"Skipping invalid line (not enough parts): {line}")

    if not file_found:
        messagebox.showerror(
            "File Not Found", "The selected file was not found in the vault.")




def add_file(event=None):
    if event:
        file_path = event.data.strip()
    else:
        
        file_path = filedialog.askopenfilename(title="Select File to Add")

    if file_path:
        
        print(f"File selected: {file_path}")
        email_popup(file_path)


def email_popup(file_path):
    
    popup = Toplevel(vault_app)
    popup.title("Enter Email")
    popup.geometry("300x200")

    
    Label(popup, text="Enter Your Email:").pack(pady=10)
    email_entry = Entry(popup)
    email_entry.pack(pady=10)

    def send_otp_and_verify():
        email = email_entry.get().strip()  
        if not email:
            messagebox.showerror("Error", "Email is required.")
            return

        
        send_otp(email)

        
        otp_popup(email, file_path)  

        popup.destroy() 

    
    Button(popup, text="Submit", command=send_otp_and_verify).pack(pady=10)


def otp_popup(user_email, file_path):
    
    otp_window = Toplevel(vault_app)
    otp_window.title("Enter OTP")
    otp_window.geometry("300x200")

    
    Label(otp_window, text="Enter OTP:", font=("Courier", 12)).pack(pady=10)
    otp_entry = Entry(otp_window, font=("Courier", 12))
    otp_entry.pack(pady=10)

    def verify_otp_and_encrypt():
        entered_otp = otp_entry.get().strip() 
        if entered_otp == otp_sent: 
            
            encrypted_file_path = encrypt_file(file_path, user_email)
            messagebox.showinfo(
                "Success", f"File added and encrypted for {user_email}.")

            
            send_confirmation_email(user_email, encrypted_file_path)

            otp_window.destroy()  
            refresh_file_list()  

        else:
            messagebox.showerror(
                "Invalid OTP", "The OTP entered is incorrect.")

    
    Button(otp_window, text="Submit", command=verify_otp_and_encrypt,
           font=("Courier", 12)).pack(pady=10)


def send_confirmation_email(user_email, encrypted_file_path):
    try:
        
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            
            server.login("biocryptprogram@gmail.com", "")

            subject = "File Encryption Confirmation"
            body = f"Hello,\n\nYour file has been successfully encrypted and added to the vault.\n\nEncrypted file path: {encrypted_file_path}\n\nBest regards,\nVault Team"

            message = f"Subject: {subject}\n\n{body}"

            
            server.sendmail("your_email@gmail.com", user_email, message)

        messagebox.showinfo("Confirmation Email Sent",
                            "A confirmation email has been sent to the provided address.")

    except Exception as e:
        messagebox.showerror(
            "Error", f"Failed to send confirmation email: {str(e)}")


# GUI setup

vault_app = TkinterDnD.Tk() 
vault_app.title("Vault")
vault_app.geometry("600x500")
vault_app.resizable(False, False)
vault_app.config(bg=var1["bg"])
Label(vault_app, text="The Vault", bg=var1["bg"], fg=var2["fg"], font=(
    "Courier", 55, "bold")).pack(pady=10)

file_listbox = Listbox(
    vault_app,
    font=("Courier", 12),
    width=90,
    height=20,
    fg=var1["bg"],
    bg=var2["fg"]
)
file_listbox.pack(pady=10)


Button(vault_app, text="   Retrive    ", command=lambda: file_action("get"),
       bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12)).pack(pady=3)
Button(vault_app, text="    Delete    ", command=lambda: file_action("delete"),
       bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12)).pack(pady=3)



vault_app.drop_target_register(DND_FILES)
vault_app.dnd_bind('<<Drop>>', add_file)


Button(vault_app, text="     Add      ", command=add_file,
       bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12)).pack(pady=3)


refresh_file_list()

vault_app.mainloop()
