from sub_programs.safe_mail import run as run_safe_mail
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import csv
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import csv
import os
import sys


def run_ipfs():
    import tkinter as tk
    from tkinter import messagebox, filedialog, simpledialog, Label
    import web3
    import os
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import requests
    import json
    import time
    from Crypto.Util.Padding import unpad
    import csv
    import sys
    import csv
    from web3 import Web3
    import platform
    import subprocess
    from pathlib import Path

    def start_ipfs_daemon():
        """
        Open a new terminal and run the `ipfs daemon` command in the user's home directory.
        """
        home_dir = os.path.expanduser("~")  # Get user's home directory

        try:
            if sys.platform == "win32":
                # Windows: Use `start` to launch cmd and set working directory
                subprocess.Popen(
                    ["start", "cmd", "/k", f"cd /d {home_dir} && ipfs daemon"],
                    shell=True
                )
            elif sys.platform == "darwin":
                # macOS: Open Terminal and run command in home directory
                command = f'cd {home_dir} && ipfs daemon'
                subprocess.Popen([
                    "osascript", "-e",
                    f'tell application "Terminal" to do script "{command}"'
                ])
            elif sys.platform.startswith("linux"):
                # Linux: Open gnome-terminal and set working directory
                subprocess.Popen([
                    "gnome-terminal", "--working-directory", home_dir, "--", "ipfs", "daemon"
                ])
            else:
                raise OSError("Unsupported operating system")

            print("IPFS daemon started in a new terminal at home directory.")
        except Exception as e:
            print(f"Failed to start IPFS daemon: {e}")

    start_ipfs_daemon()

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

    USER_INFO_FILE = resource_path('data/user_info.csv')

    def save_user_info(contract_address, account_address, private_key):
        """ Save user info to a CSV file. """
        os.makedirs(os.path.dirname(USER_INFO_FILE),
                    exist_ok=True)  # Create 'data' folder if it doesn't exist
        with open(USER_INFO_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([contract_address, account_address, private_key])

    def load_user_info():
        """ Load user info from the CSV file. """
        try:
            with open(USER_INFO_FILE, mode='r') as file:
                reader = csv.reader(file)
                row = next(reader)
                # Contract Address, Account Address, Private Key
                return row[0], row[1], row[2]
        except (FileNotFoundError, StopIteration):
            return None, None, None

    def ask_user_info():
        """ Ask the user for their info using a GUI. """
        def on_submit():
            contract_address = contract_address_entry.get()
            account_address = account_address_entry.get()
            private_key = private_key_entry.get()

            if not contract_address or not account_address or not private_key:
                messagebox.showerror("Error", "All fields are required!")
                return

            save_user_info(contract_address, account_address, private_key)
            root.destroy()

        # Create the main window
        root = tk.Tk()
        root.title("User Information")
        root.attributes('-topmost', True)
        # Create and place labels and entry fields
        tk.Label(root, text="Contract Address:").grid(
            row=0, column=0, padx=10, pady=5)
        contract_address_entry = tk.Entry(root, width=40)
        contract_address_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(root, text="Account Address:").grid(
            row=1, column=0, padx=10, pady=5)
        account_address_entry = tk.Entry(root, width=40)
        account_address_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(root, text="Private Key:").grid(
            row=2, column=0, padx=10, pady=5)
        private_key_entry = tk.Entry(
            root, width=40, show="*")  # Mask private key input
        private_key_entry.grid(row=2, column=1, padx=10, pady=5)

        # Submit button
        submit_button = tk.Button(root, text="Submit", command=on_submit)
        submit_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Run the GUI event loop

    def get_user_info():
        """ Load user info or prompt the user to enter it using a GUI. """
        contract_address, account_address, private_key = load_user_info()
        if not contract_address or not account_address or not private_key:
            ask_user_info()  # Prompt the user to enter their info
            contract_address, account_address, private_key = load_user_info()  # Reload after saving
        return contract_address, account_address, private_key

    def upload_to_ipfs(file_path):
        """ Upload a file to IPFS and return its CID. """
        with open(file_path, "rb") as file:
            response = requests.post(
                f"{IPFS_API_URL}/add", files={"file": file})
            return response.json()["Hash"] if response.status_code == 200 else None

    # Web3 & IPFS Configuration
    INFURA_URL = "https://sepolia.infura.io/v3/7e7926d9887b4d5ca773c9733f6600f3"
    IPFS_API_URL = "http://127.0.0.1:5001/api/v0"
    CONTRACT_ADDRESS, ACCOUNT_ADDRESS, PRIVATE_KEY = get_user_info()

    # Contract ABI
    YOUR_CONTRACT_ABI = [
        {
            "inputs": [
                {
                    "internalType": "string",
                    "name": "cid",
                    "type": "string"
                }
            ],
            "name": "storeFileCID",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "getStoredCIDs",
            "outputs": [
                {
                    "internalType": "string[]",
                    "name": "",
                    "type": "string[]"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ]

    # Initialize Web3 and contract
    w3 = Web3(Web3.HTTPProvider(INFURA_URL))
    if not w3.is_connected():
        raise Exception("Failed to connect to Web3 provider")

    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=YOUR_CONTRACT_ABI)


# Define file paths using resource_path
    KEYS_FILE = resource_path('data/encryption_keys.json')
    FILE_NAMES_FILE = resource_path('data/file_names.json')
    USER_INFO_FILE = resource_path('data/user_info.csv')
    CSV_FILE = resource_path('data/theme_settings.csv')

    def save_encryption_key(cid, key):
        """ Save the encryption key associated with a CID in a JSON file. """
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(KEYS_FILE), exist_ok=True)
            print(f"Directory exists: {os.path.dirname(KEYS_FILE)}")  # Debug

            # Initialize keys as an empty dictionary if the file doesn't exist or is empty
            if os.path.exists(KEYS_FILE) and os.path.getsize(KEYS_FILE) > 0:
                with open(KEYS_FILE, "r") as f:
                    try:
                        keys = json.load(f)
                        print("Loaded existing encryption keys:", keys)  # Debug
                    except json.JSONDecodeError:
                        print("File is corrupted. Initializing empty dictionary.")
                        keys = {}
            else:
                print("File does not exist or is empty. Initializing empty dictionary.")
                keys = {}

            # Add the new CID and key to the dictionary
            keys[cid] = key.hex()
            print("Updated encryption keys:", keys)  # Debug

            # Save the updated dictionary back to the file
            with open(KEYS_FILE, "w") as f:
                # Pretty-print JSON for readability
                json.dump(keys, f, indent=4)
            print("Encryption key saved successfully.")  # Debug
        except Exception as e:
            print(f"Error saving encryption key: {e}")

    def encrypt_file(file_path):
        key = os.urandom(32)
        cipher = AES.new(key, AES.MODE_CBC)

        with open(file_path, "rb") as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        encrypted_file_path = file_path + ".enc"

        with open(encrypted_file_path, "wb") as f:
            f.write(cipher.iv + ciphertext)

        return encrypted_file_path, key

    def upload_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        file_name = simpledialog.askstring(
            "File Name", "Enter the name for the file:")
        if not file_name:
            messagebox.showerror("Error", "File name is required!")
            return

        # Encrypt the file
        encrypted_file, encryption_key = encrypt_file(file_path)

        # Upload the encrypted file to IPFS
        cid = upload_to_ipfs(encrypted_file)
        if not cid:
            messagebox.showerror("Error", "Failed to upload file to IPFS.")
            return

        # Save the encryption key with the corresponding CID
        # Debug
        print(
            f"Calling save_encryption_key with CID: {cid} and Key: {encryption_key.hex()}")
        save_encryption_key(cid, encryption_key)

        # Save the file name with the corresponding CID
        # Debug
        print(
            f"Calling save_file_name with CID: {cid} and File Name: {file_name}")
        save_file_name(cid, file_name)

        # Store the CID on the blockchain
        tx_hash = store_cid_on_blockchain(cid)

        # Remove the temporary encrypted file
        os.remove(encrypted_file)

        messagebox.showinfo(
            "Success", f"File uploaded! CID: {cid}\nTx Hash: {tx_hash}")

    def store_cid_on_blockchain(cid):
        nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS)
        print(f"Using nonce: {nonce}")

        txn = contract.functions.storeFileCID(cid).build_transaction({
            "from": ACCOUNT_ADDRESS,
            "nonce": nonce,
            "gas": 100000,  # ⬆️ Increased gas
            "gasPrice": w3.eth.gas_price,
        })

        signed_txn = w3.eth.account.sign_transaction(txn, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        if receipt['status'] == 1:
            print(f"Transaction successful! CID stored: {cid}")
        else:
            print("Transaction failed! Check gas and nonce.")

        return tx_hash.hex()

    # Define file paths using resource_path
    FILE_NAMES_FILE = resource_path('file_names.json')

    def get_data_dir():
        """ Get the platform-specific data directory. """
        if platform.system() == "Windows":
            return Path(os.getenv('APPDATA')) / "BioCrypt"
        elif platform.system() == "Darwin":  # macOS
            return Path.home() / "Library" / "Application Support" / "BioCrypt"
        else:  # Linux and others
            return Path.home() / ".biocrypt"

    # Use resource_path for development and bundled environments
    # Use resource_path to ensure correct path
    DATA_DIR = resource_path('data')
    FILE_NAMES_FILE = os.path.join(DATA_DIR, "file_names.json")

    def save_file_name(cid, file_name):
        """ Save the file name associated with a CID in a JSON file. """
        try:
            # Debug
            print(f"Saving file name: CID={cid}, File Name={file_name}")

            # Ensure the directory exists
            os.makedirs(DATA_DIR, exist_ok=True)
            print(f"Directory exists: {DATA_DIR}")  # Debug

            # Initialize file_names as an empty dictionary if the file doesn't exist or is empty
            if os.path.exists(FILE_NAMES_FILE) and os.path.getsize(FILE_NAMES_FILE) > 0:
                with open(FILE_NAMES_FILE, "r") as f:
                    try:
                        file_names = json.load(f)
                        print("Loaded existing file names:",
                              file_names)  # Debug
                    except json.JSONDecodeError:
                        print("File is corrupted. Initializing empty dictionary.")
                        file_names = {}
            else:
                print("File does not exist or is empty. Initializing empty dictionary.")
                file_names = {}

            # Add the new CID and file name to the dictionary
            file_names[cid] = file_name
            print("Updated file names:", file_names)  # Debug

            # Save the updated dictionary back to the file
            with open(FILE_NAMES_FILE, "w") as f:
                # Pretty-print JSON for readability
                json.dump(file_names, f, indent=4)
            print("File saved successfully.")  # Debug
        except Exception as e:
            print(f"Error saving file name: {e}")

    def upload_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        file_name = simpledialog.askstring(
            "File Name", "Enter the name for the file:")
        if not file_name:
            messagebox.showerror("Error", "File name is required!")
            return

        encrypted_file, encryption_key = encrypt_file(file_path)

        # Save the encryption key with the corresponding CID
        cid = upload_to_ipfs(encrypted_file)
        if not cid:
            messagebox.showerror("Error", "Failed to upload file to IPFS.")
            return

        save_encryption_key(cid, encryption_key)
        # Ensure this line is present and called
        # Debug
        print(
            f"Calling save_file_name with CID: {cid} and File Name: {file_name}")
        save_file_name(cid, file_name)

        tx_hash = store_cid_on_blockchain(cid)

        os.remove(encrypted_file)

        messagebox.showinfo(
            "Success", f"File uploaded! CID: {cid}\nTx Hash: {tx_hash}")

    def list_stored_files():
        """ List all stored files by fetching CIDs from the blockchain and displaying their names. """
        try:
            # Load file names
            if os.path.exists(FILE_NAMES_FILE) and os.path.getsize(FILE_NAMES_FILE) > 0:
                with open(FILE_NAMES_FILE, "r") as f:
                    try:
                        file_names = json.load(f)
                        print("Loaded file names:", file_names)  # Debug
                    except json.JSONDecodeError:
                        print("File is corrupted. Using empty dictionary.")
                        file_names = {}
            else:
                print("File does not exist or is empty. Using empty dictionary.")
                file_names = {}

            # Fetch CIDs from the blockchain
            print("Fetching stored files...")  # Debugging
            cids = contract.functions.getStoredCIDs().call()
            print("Received CIDs:", cids)  # Debugging

            # Update the listbox
            file_listbox.config(state=tk.NORMAL)
            file_listbox.delete(0, tk.END)  # Clear previous entries

            for cid in cids:
                # Use file name if available, otherwise CID
                display_name = file_names.get(cid, cid)
                file_listbox.insert(tk.END, display_name)
            print("List updated successfully!")  # Debugging
        except Exception as e:
            print(f"Error listing stored files: {e}")
    # IPFS Gateway URLs
    IPFS_GATEWAYS = [
        "https://ipfs.io/ipfs/",
        "https://cloudflare-ipfs.com/ipfs/",
        "https://gateway.pinata.cloud/ipfs/",
        "https://dweb.link/ipfs/"
        "https://ipfs.io/ipfs/",
        "https://gateway.pinata.cloud/ipfs/",
        "https://cloudflare-ipfs.com/ipfs/",
        "https://dweb.link/ipfs/",
        "https://gateway.ipfs.io/ipfs/",
        "https://ipfs.infura.io/ipfs/",
        "https://hardbin.com/ipfs/",
        "https://ipfs.eternum.io/ipfs/",
    ]

    def retrieve_file_with_retry(cid, max_attempts=5):
        backoff = 5  # Start with 5 seconds
        for attempt in range(max_attempts):
            for gateway in IPFS_GATEWAYS:
                url = f"{gateway}{cid}"
                print(f"Trying {url} (Attempt {attempt + 1})")

                try:
                    response = requests.get(
                        url, timeout=60)  # Increase timeout
                    if response.status_code == 200:
                        return response.content
                    else:
                        print(
                            f"❌ Failed with {gateway}: {response.status_code} {response.reason}")

                except requests.RequestException as e:
                    print(f"❌ Error with {gateway}: {e}")

            if attempt < max_attempts - 1:
                print(
                    f"Retrying in {backoff} seconds... ({attempt + 1}/{max_attempts})")
                time.sleep(backoff)
                backoff *= 2  # Exponential backoff

        print("❌ All retrieval attempts failed.")
        return None
    KEYS_FILE = resource_path('data/encryption_keys.json')

    def retrieve_and_decrypt():
        selected = file_listbox.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select a file to retrieve!")
            return

        display_name = file_listbox.get(selected[0])  # Get the display name

        # Load file names to map display name back to CID
        try:
            with open(FILE_NAMES_FILE, "r") as f:
                file_names = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showerror(
                "Error", "File names file missing or corrupted!")
            return

        # Find the CID corresponding to the display name
        cid = None
        for key, value in file_names.items():
            if value == display_name:
                cid = key
                break  # FIX: Direct dictionary lookup

        if not cid:
            messagebox.showerror(
                "Error", "CID not found for the selected file!")
            return

        # Authenticate using Touch ID **before retrieving the file**
        if not authenticate_touch_id():
            messagebox.showerror("Error", "Authentication Failed!")
            return

        file_data = retrieve_file_with_retry(cid)

        if file_data is None:
            messagebox.showerror("Error", "Failed to retrieve file from IPFS!")
            return

        # Load encryption keys
        try:
            with open(KEYS_FILE, "r") as key_file:
                encryption_keys = json.load(key_file)
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showerror(
                "Error", "Encryption keys file missing or corrupted!")
            return

        # Get the encryption key for this CID
        encryption_key = encryption_keys.get(cid)

        if not encryption_key:
            messagebox.showerror(
                "Error", "No encryption key found for this file!")
            return

        encryption_key = bytes.fromhex(encryption_key)

        # Extract IV and decrypt
        iv = file_data[:16]  # Extract IV
        ciphertext = file_data[16:]  # Extract actual encrypted content

        try:
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except (ValueError, KeyError):
            messagebox.showerror(
                "Error", "Decryption failed! Invalid key or corrupted file.")
            return

        # Ask the user for a save location
        root = tk.Tk()
        root.withdraw()  # Hide the main window

        save_path = filedialog.asksaveasfilename(
            defaultextension="",
            initialfile="DecryptedFile",
            title="Save Decrypted File",
            filetypes=[("All Files", "*.*")]
        )

        if save_path:  # If user selects a save location
            with open(save_path, "wb") as f:
                f.write(plaintext)
            messagebox.showinfo(
                "Success", f"File decrypted successfully!\nSaved as: {save_path}")
        else:
            messagebox.showinfo("Cancelled", "Save operation cancelled.")

    def authenticate_touch_id():
        try:
            result = os.system("sudo /usr/bin/bioutil -c")
            if result == 0:
                print("✅ Touch ID authentication successful")
                return True
            else:
                print("❌ Touch ID authentication failed with exit code:", result)
                return False
        except Exception as e:
            print("❌ Error in Touch ID authentication:", e)
            return False

    # GUI Setup
    root = tk.Tk()
    root.title("BioCrypt - Secure File Storage")
    root.geometry("600x500")
    root.config(bg=var1["bg"])
    Label(root, text="ChainSpace", bg=var1["bg"], fg=var2["fg"], font=(
        "Courier", 55, "bold")).pack(pady=10)

    file_listbox = tk.Listbox(root, width=66, height=18,
                              fg=var1["bg"], bg=var2["fg"], selectmode=tk.SINGLE)
    file_listbox.pack(pady=10)
    file_listbox.config(state=tk.NORMAL)

    tk.Button(root, text="     Refresh      ", command=list_stored_files,
              bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12)).pack(pady=2)
    root.after(1, list_stored_files)
    tk.Button(root, text="   Upload File    ", command=upload_file,
              bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12)).pack(pady=2)
    tk.Button(root, text="Retrieve & Decrypt", command=retrieve_and_decrypt,
              bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12)).pack(pady=2)
    root.mainloop()

    if __name__ == "__main__":
        start_ipfs_daemon()

######################################################################################################################################


def run_FAQ():

    import customtkinter as ctk
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")

    class FAQApp(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.title("BioCrypt FAQ")
            self.geometry("500x600")
            self.resizable(False, False)

            self.scrollable_frame = ctk.CTkScrollableFrame(self)
            self.scrollable_frame.pack(
                fill="both", expand=True, padx=10, pady=10)

            self.faq_data = [
                ("What is BioCrypt?", "BioCrypt is a file encryption system that uses fingerprint authentication instead of passwords."),
                ("How does BioCrypt work?",
                 "It scans your fingerprint to generate a unique encryption key for encrypting or decrypting files."),
                ("Is BioCrypt user-friendly for non-technical users?",
                 "Yes, it has a simple and intuitive interface."),
                ("Can BioCrypt be used by organizations?",
                 "Yes, it offers secure file management solutions for businesses."),
                ("Does BioCrypt store personal data?",
                 "No, fingerprint data is stored locally and never uploaded to a server."),
                ("Is BioCrypt available for Windows and Mac?",
                 "Yes, with future plans for a mobile version."),
                ("How does BioCrypt protect against cyberattacks?",
                 "It uses AES-256 encryption, biometric authentication, blockchain technology, and IPFS-based decentralized storage."),
                ("What is Safe Mail?",
                 "A feature for securely sending encrypted files via email with a separate decryption key."),
                ("How does TimeGuard work?",
                 "t automatically deletes encrypted files after a set time or failed access attempts."),
                ("What is SecureFileBeam?",
                 "A feature for securely transferring encrypted files via Bluetooth."),
                ("Can I share encrypted files with other BioCrypt users?",
                 "Yes, via SafeMail or SecureFileBeam with encryption protection."),
                ("How does BioCrypt prevent Man-in-the-Middle attacks?",
                 "It uses end-to-end encryption to secure file transfers."),
            ]

            self.current_open_label = None
            self.create_faq_list()

        def create_faq_list(self):
            for question, answer in self.faq_data:
                faq_frame = ctk.CTkFrame(self.scrollable_frame)
                faq_frame.pack(fill="x", pady=5)

                question_button = ctk.CTkButton(
                    faq_frame, text=question, corner_radius=15)
                question_button.pack(fill="x")

                answer_label = ctk.CTkLabel(
                    faq_frame, text=answer, wraplength=350)
                answer_label.pack(fill="x", padx=10, pady=5)
                answer_label.pack_forget()

                question_button.configure(
                    command=lambda btn=question_button: self.toggle_answer(btn))

                setattr(question_button, "answer_label", answer_label)

            self.answer_label = ctk.CTkLabel(
                self, text="Select a question to see the answer.", wraplength=700)
            self.answer_label.pack(pady=10)

        def toggle_answer(self, button):

            if self.current_open_label and self.current_open_label != button.answer_label:
                self.current_open_label.pack_forget()

            if button.answer_label.winfo_ismapped():
                button.answer_label.pack_forget()
                self.current_open_label = None
            else:
                button.answer_label.pack(fill="x", padx=10, pady=5)
                self.current_open_label = button.answer_label

    if __name__ == "__main__":
        app = FAQApp()
        app.mainloop()

######################################################################################################################################


def run_vault(parent_root=None):
    import os
    import random
    import smtplib
    from tkinter import Tk, Label, Button, Listbox, Toplevel, Entry, filedialog, messagebox
    # Remove tkinterdnd2 imports
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    import base64
    import csv
    import sys

    def resource_path(relative_path):
        """Get absolute path to resource, works for dev and PyInstaller bundle."""
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    # Ensure 'data/vault' folder exists using resource_path
    os.makedirs(resource_path("data/vault"), exist_ok=True)

    CSV_FILE = resource_path("data/theme_settings.csv")
    LOCAL_STORAGE_FILE = resource_path("data/local_storage.txt")
    VAULT_FOLDER = resource_path("data/vault")

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
    file_owners = {}  # Maps files to their owner: {file_path: email}

    # Fixed 256-bit key (32 bytes)
    # Predefined key (you can change this to any 32-byte value)
    fixed_key = b"BecaUKnowInAMomentItCouldAllPoow"

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
        cipher = Cipher(algorithms.AES(fixed_key),
                        modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted file to the 'vault' folder
        # Add .enc extension for encrypted files
        file_name = os.path.basename(file_path) + ".enc"
        encrypted_file_path = os.path.join(VAULT_FOLDER, file_name)

        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + encrypted_data)  # Save IV + encrypted data

        # Save the file details to local storage
        with open(LOCAL_STORAGE_FILE, "a") as storage_file:
            storage_file.write(f"{encrypted_file_path} {user_email}\n")

        return encrypted_file_path

    # Decrypt Function (with fixed key)

    def decrypt_file(file_path, restore_folder):
        with open(file_path, 'rb') as f:
            iv = f.read(16)  # Read the IV (first 16 bytes)
            encrypted_data = f.read()  # Read the rest as the encrypted data

        # Decrypt the data using AES in CBC mode with the fixed key
        cipher = Cipher(algorithms.AES(fixed_key),
                        modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(
            encrypted_data) + decryptor.finalize()

        # Unpad the decrypted data to get the original file content
        unpadder = padding.PKCS7(128).unpadder()
        original_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Save the restored (decrypted) file to the specified folder
        restored_file_path = os.path.join(
            restore_folder, os.path.basename(file_path).replace(".enc", ""))

        with open(restored_file_path, 'wb') as f:
            f.write(original_data)

        return restored_file_path

    # Function to generate and send OTP via email

    def send_otp(email):
        otp = str(random.randint(100000, 999999))  # Generate OTP
        try:
            # Send OTP via email
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                # Replace with actual credentials
                server.login("",
                             "")
                message = f"Subject: Vault OTP Verification\n\nYour OTP is: {otp}"
                server.sendmail("your_email@gmail.com", email, message)

            messagebox.showinfo("OTP Sent",
                                f"An OTP has been sent to {email}. Please enter it to confirm.")
            return otp
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send OTP: {str(e)}")
            return None

    # Function to verify OTP and decrypt the file

    def verify_otp(action, file_path, email, sent_otp):
        def check_otp():
            entered_otp = otp_entry.get().strip()  # Get OTP entered by user
            if entered_otp == sent_otp:
                if action == "get":
                    # Ask for destination folder to restore the file
                    restore_folder = filedialog.askdirectory(
                        title="Select Folder to Restore the File")
                    if restore_folder:
                        # Decrypt the file and save it to the destination folder
                        restored_file_path = decrypt_file(
                            file_path, restore_folder)
                        messagebox.showinfo(
                            "File Restored", f"File has been restored to {restore_folder}.")
                    refresh_file_list()
                elif action == "delete":
                    os.remove(file_path)  # Delete the file from the vault
                    messagebox.showinfo(
                        "File Deleted", "The file has been successfully deleted.")
                    refresh_file_list()
                otp_window.destroy()
            else:
                messagebox.showerror(
                    "Invalid OTP", "The OTP entered is incorrect.")

        # Create OTP input window
        otp_window = Toplevel()
        otp_window.title("Enter OTP")
        otp_window.geometry("300x200")
        Label(otp_window, text="Enter OTP:",
              font=("Courier", 12)).pack(pady=10)
        otp_entry = Entry(otp_window, font=("Courier", 12))
        otp_entry.pack(pady=10)
        Button(otp_window, text="Submit", command=check_otp,
               font=("Courier", 12)).pack(pady=10)

    # Function to refresh the file list display for the user

    def refresh_file_list():
        file_listbox.delete(0, "end")
        if os.path.exists(VAULT_FOLDER):
            for file_name in os.listdir(VAULT_FOLDER):
                if file_name.endswith(".enc"):  # Show only encrypted files
                    file_listbox.insert("end", file_name)

    def file_action(action):
        selected_indices = file_listbox.curselection()

        if not selected_indices:
            messagebox.showerror(
                "No File Selected", "Please select a file from the list before performing an action.")
            return

        selected_file = file_listbox.get(selected_indices)
        # Get the selected file's name with .enc
        selected_filename = os.path.basename(selected_file).strip()
        file_found = False

        # Loop through lines in the local storage
        with open(LOCAL_STORAGE_FILE, "r") as file:
            for line in file:
                line = line.strip()  # Remove leading/trailing spaces

                # Skip empty lines
                if not line:
                    continue

                # Debug: Print each line to check its format
                # Add quotes to see if extra spaces exist
                print(f"Line in storage: '{line}'")

                # Split the line by spaces
                parts = line.split()

                # Ensure we have at least two parts: file path and email
                if len(parts) >= 2:
                    # The last part should be the email, and the rest should be the file path
                    email = parts[-1].strip()
                    # Combine everything except the last part as the file path
                    file_path = " ".join(parts[:-1]).strip()

                    # Get the stored file path with .enc
                    stored_filename = os.path.basename(file_path).strip()

                    # Debug: Print out the parts
                    print(f"File path: '{file_path}', Email: '{email}'")

                    # Check if the selected file matches the stored file path
                    # Compare full file path (including .enc)
                    if selected_filename == stored_filename:
                        file_found = True
                        sent_otp = send_otp(email)  # Get the generated OTP
                        if sent_otp:  # Only verify if OTP was sent successfully
                            verify_otp(action, file_path, email, sent_otp)
                        break
                else:
                    # Log invalid lines for debugging
                    print(f"Skipping invalid line (not enough parts): {line}")

        if not file_found:
            messagebox.showerror(
                "File Not Found", "The selected file was not found in the vault.")

    # Function to handle file drops (drag-and-drop)

    def add_file(event=None):
        if event:
            file_path = event.data.strip()
        else:
            # Open file dialog if event is None (button click)
            file_path = filedialog.askopenfilename(title="Select File to Add")

        if file_path:
            # Debugging: print selected file path
            print(f"File selected: {file_path}")
            email_popup(file_path)

    def email_popup(file_path):
        # Create a new popup window to input the email
        popup = Toplevel()
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
            sent_otp = send_otp(email)  # Get the generated OTP
            if sent_otp:  # Only proceed if OTP was sent successfully
                otp_popup(email, file_path, sent_otp)

            popup.destroy()  # Close the email input window

        # Submit button to send OTP and open OTP window
        Button(popup, text="Submit", command=send_otp_and_verify).pack(pady=10)

    def otp_popup(user_email, file_path, sent_otp):
        # Create OTP input window for OTP verification
        otp_window = Toplevel()
        otp_window.title("Enter OTP")
        otp_window.geometry("300x200")

        # Add label and entry for OTP input
        Label(otp_window, text="Enter OTP:",
              font=("Courier", 12)).pack(pady=10)
        otp_entry = Entry(otp_window, font=("Courier", 12))
        otp_entry.pack(pady=10)

        def verify_otp_and_encrypt():
            entered_otp = otp_entry.get().strip()  # Get OTP entered by user
            if entered_otp == sent_otp:  # Check if entered OTP matches sent OTP
                # Encrypt the file and send a confirmation email
                encrypted_file_path = encrypt_file(file_path, user_email)
                messagebox.showinfo(
                    "Success", f"File added and encrypted for {user_email}.")

                # Send confirmation email after successful encryption
                send_confirmation_email(user_email, encrypted_file_path)

                otp_window.destroy()  # Close OTP window
                refresh_file_list()  # Refresh file list to show the new file

            else:
                messagebox.showerror(
                    "Invalid OTP", "The OTP entered is incorrect.")

        # Submit button to verify OTP and proceed
        Button(otp_window, text="Submit", command=verify_otp_and_encrypt,
               font=("Courier", 12)).pack(pady=10)

    def send_confirmation_email(user_email, encrypted_file_path):
        try:
            # Set up the email server
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                # Replace with your credentials
                server.login("",
                             "")

                subject = "File Encryption Confirmation"
                body = f"Hello,\n\nYour file has been successfully encrypted and added to the vault.\n\nEncrypted file path: {encrypted_file_path}\n\nBest regards,\nVault Team"

                message = f"Subject: {subject}\n\n{body}"

                # Send the email
                server.sendmail("your_email@gmail.com", user_email, message)

            messagebox.showinfo("Confirmation Email Sent",
                                "A confirmation email has been sent to the provided address.")

        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to send confirmation email: {str(e)}")

    # GUI setup - Replace TkinterDnD with normal Tk window
    vault_window = tk.Tk()
    vault_window.title("Vault")
    vault_window.geometry("600x500")
    vault_window.resizable(False, False)
    vault_window.config(bg=var1["bg"])

    # Remove drag & drop registration

    Label(vault_window, text="The Vault", bg=var1["bg"], fg=var2["fg"],
          font=("Courier", 55, "bold")).pack(pady=10)

    file_listbox = Listbox(
        vault_window,
        font=("Courier", 12),
        width=90,
        height=20,
        fg=var1["bg"],
        bg=var2["fg"]
    )
    file_listbox.pack(pady=10)

    # Replace add_file function with simple file dialog
    def add_file():
        file_path = filedialog.askopenfilename(title="Select File to Add")
        if file_path:
            print(f"File selected: {file_path}")
            email_popup(file_path)

    Button(vault_window, text="   Retrieve    ", command=lambda: file_action("get"),
           bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0,
           highlightthickness=0, font=("Courier", 12)).pack(pady=3)

    Button(vault_window, text="    Delete    ", command=lambda: file_action("delete"),
           bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0,
           highlightthickness=0, font=("Courier", 12)).pack(pady=3)

    Button(vault_window, text="     Add      ", command=add_file,
           bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0,
           highlightthickness=0, font=("Courier", 12)).pack(pady=3)

    refresh_file_list()
    vault_window.mainloop()

######################################################################################################################################


def resource_path(relative_path):
    """ Get absolute path to resource, works for development and PyInstaller """
    if getattr(sys, 'frozen', False):
        # Running inside PyInstaller bundle
        base_path = sys._MEIPASS
    else:
        # Running in normal Python (development mode)
        base_path = os.path.abspath(".")  # Fixed: Changed 'is' to '='
    return os.path.join(base_path, relative_path)


CSV_FILE = resource_path("data/theme_settings.csv")

# Example global variables
selected_value = None
var1 = {"bg": "#ffffff"}
var2 = {"fg": "#000000"}


def save_to_csv(var1, var2):
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([var1["bg"], var2["fg"]])


def read_from_csv():
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            row = next(reader)
            return row[0], row[1]
    except (FileNotFoundError, StopIteration):
        return "#ffffff", "#000000"


def update_variables(theme):
    global var1, var2
    themes = {
        "Default": {"bg": "#ffffff", "fg": "#000000"},
        "Dark": {"bg": "#121212", "fg": "#ffffff"},
        # Add all your other themes here
    }
    selected_theme = themes.get(theme, themes["Default"])
    var1["bg"] = selected_theme["bg"]
    var2["fg"] = selected_theme["fg"]


def restart_application():
    python = sys.executable
    os.execl(python, python, *sys.argv)


def open_settings():
    global selected_value, var1, var2

    settings_window = tk.Toplevel()
    settings_window.title("Settings")
    settings_window.resizable(False, False)
    settings_window.geometry("300x200")

    label = tk.Label(settings_window, text="Choose a theme:")
    label.pack(pady=10)

    options = ["Default", "Dark", "Arcane", "2077", "Fallout", "Light",
               "Pink", "JINX", "VI", "JINX-CLOUD", "Powder", "High Contrast 1", "High Contrast 2"]
    drop_down = ttk.Combobox(settings_window, values=options, state="readonly")
    drop_down.pack(pady=10)

    # Set the dropdown to the currently saved theme
    current_bg, current_fg = read_from_csv()
    current_theme = "Default"  # fallback

    for theme, colors in {
        "Default": {"bg": "#ffffff", "fg": "#000000"},
        "Dark": {"bg": "#121212", "fg": "#ffffff"},
        # Add the rest here
    }.items():
        if colors["bg"] == current_bg and colors["fg"] == current_fg:
            current_theme = theme
            break

    drop_down.set(current_theme)

    def save_selection():
        global selected_value, var1, var2
        selected_value = drop_down.get()
        update_variables(selected_value)
        save_to_csv(var1, var2)

        response = messagebox.askyesno(
            "Restart Required", "You need to restart the application to apply the theme. Do you want to restart?")
        if response:
            restart_application()
        else:
            settings_window.destroy()

    save_button = tk.Button(
        settings_window, text="Save Selection", command=save_selection)
    save_button.pack(pady=20)

    settings_window.mainloop()


def update_variables(value):
    global var1, var2
    if value == "Default":
        var1 = {"bg": "#05012E"}
        var2 = {"fg": "#00FF00"}

    elif value == "Dark":
        var1 = {"bg": "#030202"}
        var2 = {"fg": "#2e2e2e"}
    elif value == "Arcane":
        var1 = {"bg": "#060715"}
        var2 = {"fg": "#d43c5d"}
    elif value == "2077":
        var1 = {"bg": "#081d15"}
        var2 = {"fg": "#fefc75"}
    elif value == "Fallout":
        var1 = {"bg": "#0c2011"}
        var2 = {"fg": "#73df92"}
    elif value == "Light":
        var1 = {"bg": "#e4e4e4"}
        var2 = {"fg": "#000000"}
    elif value == "Pink":
        var1 = {"bg": "#DE3163"}
        var2 = {"fg": "#FFBF00"}
    elif value == "JINX":
        var1 = {"bg": "#324ab2"}
        var2 = {"fg": "#c71585"}
    elif value == "VI":
        var1 = {"bg": "#732735"}
        var2 = {"fg": "#EC9469"}
    elif value == "JINX-CLOUD":
        var1 = {"bg": "#9dac9d"}
        var2 = {"fg": "#384239"}
    elif value == "Powder":
        var1 = {"bg": "#b6d0e2"}
        var2 = {"fg": "#4630b9"}
    elif value == "High Contrast 1":
        var1 = {"bg": "#373b91"}
        var2 = {"fg": "#fdfdfd"}
    elif value == "High Contrast 2":
        var1 = {"bg": "#f7d84c"}
        var2 = {"fg": "#21201e"}

    print(f"Theme updated - var1: {var1}, var2: {var2}")


# Put your file inside a "data" folder


def save_to_csv(var1, var2):
    """ Save data to CSV file. """
    os.makedirs(os.path.dirname(CSV_FILE),
                exist_ok=True)  # Make sure the folder exists
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([var1["bg"], var2["fg"]])


def read_from_csv():
    """ Read data from CSV file. """
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            row = next(reader)
            return row[0], row[1]
    except (FileNotFoundError, StopIteration):
        return "#9dac9d", "#384239"  # Defaults if file not found or empty


bg_color, fg_color = read_from_csv()
var1 = {"bg": bg_color}
var2 = {"fg": fg_color}


def generate_key():
    # Use a random value to generate a key
    random_value = os.urandom(32)  # 32 bytes for AES-256
    # Hash the random value to create a key
    return hashlib.sha256(random_value).digest()


# Resource path function (unchanged)
def resource_path(relative_path):
    if getattr(sys, 'frozen', False):  # Running as a PyInstaller bundle
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Remove Arduino-related code and replace with Touch ID logic


def authenticate_with_touch_id():
    try:
        # Run a harmless sudo command to trigger Touch ID
        subprocess.run(
            ["sudo", "--validate"],
            capture_output=True,
            text=True,
            check=True,
        )
        print("Authentication successful!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Authentication failed: {e.stderr}")
        return False


def generate_key_from_touch_id():
    # Generate a secure key using a hash of a random value (for demonstration purposes)
    random_value = os.urandom(32)
    return hashlib.sha256(random_value).digest()

    # Replace the Arduino fingerprint scan function


def on_fingerprint_scan():
    if authenticate_with_touch_id():
        print("Authentication successful!")
        global key
        key = generate_key_from_touch_id()
        key_hex = hashlib.sha256(key).hexdigest()
        fingerprint_label.config(text="Touch ID Authenticated")
        key_label.config(text=f"Generated Key (SHA-256): {key_hex}")
        action_frame.place(x=430, y=400, width=300, height=120)
    else:
        print("Authentication failed.")
        fingerprint_label.config(text="Authentication failed. Try again.")


BLOCK_SIZE = 16
key = None


log_file = resource_path("data/operation_logs.csv")


def read_from_csv():

    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            row = next(reader)
            return {"bg": row[0]}, {"fg": row[1]}
    except FileNotFoundError:
        return {"bg": "#ffffff"}, {"fg": "#000000"}


def save_log(log_message):
    """Save only encryption/decryption logs to a CSV file."""
    if log_message[1] not in ["Encrypt", "Decrypt"]:
        return

    file_exists = os.path.isfile(log_file)
    with open(log_file, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Operation", "Message"])
        writer.writerow(log_message)


def debug_log(message, operation_type="General"):
    """Print debug messages and save only encryption/decryption logs."""
    if operation_type not in ["Encrypt", "Decrypt"]:
        print(f"[DEBUG] {message}")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = [timestamp, operation_type, message]
    print(f"[DEBUG] {log_message}")
    save_log(log_message)


def hash_fingerprint_id(fingerprint_id):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(str(fingerprint_id).encode('utf-8'))
    return sha256_hash.digest()[:32]


# Global variable to store the key (initialized to None)
key = None

# Fixed 16-byte IV (Initialization Vector)
iv = b"fixed_16_byte_iv"  # Must be exactly 16 bytes

# Encryption function


def encrypt_file(file_path, key, iv):
    try:
        # Read the plaintext file
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # Create AES cipher in CBC mode with the fixed IV
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the plaintext to match the block size
        padded_plaintext = pad(plaintext, AES.block_size)

        # Encrypt the padded plaintext
        ciphertext = cipher.encrypt(padded_plaintext)

        # Save the ciphertext to the encrypted file
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as f:
            f.write(ciphertext)

        return f"File encrypted successfully: {encrypted_file_path}"
    except Exception as e:
        return f"Error during encryption: {e}"

    # Decryption function


def decrypt_file(file_path, key, iv):
    try:
        # Read the ciphertext file
        with open(file_path, "rb") as f:
            ciphertext = f.read()

        # Create AES cipher in CBC mode with the fixed IV
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the ciphertext
        plaintext = cipher.decrypt(ciphertext)

        # Unpad the plaintext
        unpadded_plaintext = unpad(plaintext, AES.block_size)

        # Save the decrypted file
        decrypted_file_path = file_path.replace(".enc", "")
        with open(decrypted_file_path, "wb") as f:
            f.write(unpadded_plaintext)

        return f"File decrypted successfully: {decrypted_file_path}"
    except Exception as e:
        return f"Error during decryption: {e}"


def on_scan_button_click():
    global key
    if authenticate_with_touch_id():
        # Generate a fixed key after successful authentication
        key = b"this_is_a_fixed_32_byte_key_1234"  # Must be exactly 32 bytes
        key_hex = key.hex()  # Convert the key to hex for display
        fingerprint_label.config(text="Touch ID Authenticated")
        key_label.config(text=f"Generated Key (SHA-256): {key_hex}")
        action_frame.place(x=430, y=400, width=300, height=120)
    else:
        fingerprint_label.config(text="Authentication failed. Try again.")

    # Handle file selection and encryption/decryption


def select_file():
    global key
    if key is None:
        messagebox.showinfo(
            "Error", "Please authenticate first by scanning your fingerprint.")
        return

    file_path = filedialog.askopenfilename(title="Select a file")
    if file_path:
        if action_choice.get() == "encrypt":
            result = encrypt_file(file_path, key, iv)  # Pass the key and IV
        else:
            result = decrypt_file(file_path, key, iv)  # Pass the key and IV
        messagebox.showinfo("Result", result)


# GUI Setup
root = tk.Tk()
root.title("BioCrypt")
root.geometry("1200x700")
root.resizable(False, False)

root.configure(bg=var1["bg"])


# Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Tab 1: Encryption/Decryption
# Set the background color to dark blue
encryption_frame = tk.Frame(notebook, bg=var1["bg"])
notebook.add(encryption_frame, text="Encryption/Decryption")

label1 = tk.Label(encryption_frame, text="<̷ ",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label1.place(x=70, y=50)

label2 = tk.Label(encryption_frame, text=">̷",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label2.place(x=300, y=150)

label3 = tk.Label(encryption_frame, text="*̷",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label3.place(x=600, y=250)

# Additional labels in random spaces, avoiding the middle lane (around x=400, y=300)
label4 = tk.Label(encryption_frame, text="&̷",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 17))
label4.place(x=100, y=150)

label5 = tk.Label(encryption_frame, text="(̶",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 19))
label5.place(x=650, y=100)

label6 = tk.Label(encryption_frame, text="^̵͉̦̓̓",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 21))
label6.place(x=200, y=500)

label7 = tk.Label(encryption_frame, text="Ֆ",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 16))
label7.place(x=550, y=50)

label8 = tk.Label(encryption_frame, text="%͛͘",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label8.place(x=700, y=400)

label9 = tk.Label(encryption_frame, text="@̈́̒͠",
                  fg=var2["fg"], bg=var1["bg"], font=("Arial", 15))
label9.place(x=50, y=450)


label10 = tk.Label(encryption_frame, text="*̳",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 13))
label10.place(x=150, y=300)

label11 = tk.Label(encryption_frame, text="¿",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 17))
label11.place(x=600, y=400)

label12 = tk.Label(encryption_frame, text="x",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 16))
label12.place(x=50, y=100)

label13 = tk.Label(encryption_frame, text="x",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 21))
label13.place(x=700, y=250)


label16 = tk.Label(encryption_frame, text="¿",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label16.place(x=100, y=500)

label17 = tk.Label(encryption_frame, text="?",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 13))
label17.place(x=650, y=350)


label19 = tk.Label(encryption_frame, text="/",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 11))
label19.place(x=300, y=400)


label20 = tk.Label(encryption_frame, text="!",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 12))
label20.place(x=850, y=550)

label21 = tk.Label(encryption_frame, text="*",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 13))
label21.place(x=900, y=250)

label22 = tk.Label(encryption_frame, text="+",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 15))
label22.place(x=800, y=150)

label23 = tk.Label(encryption_frame, text="&",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 16))
label23.place(x=950, y=300)

label24 = tk.Label(encryption_frame, text="@",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 17))
label24.place(x=850, y=200)

label25 = tk.Label(encryption_frame, text="#",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 18))
label25.place(x=900, y=500)

label26 = tk.Label(encryption_frame, text="$",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 13))
label26.place(x=850, y=100)

label27 = tk.Label(encryption_frame, text="̈́̒͠",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label27.place(x=720, y=250)

label28 = tk.Label(encryption_frame, text="*",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 19))
label28.place(x=1030, y=180)

label29 = tk.Label(encryption_frame, text="!",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 12))
label29.place(x=880, y=450)

label30 = tk.Label(encryption_frame, text="?",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 16))
label30.place(x=920, y=380)

label31 = tk.Label(encryption_frame, text="$",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 20))
label31.place(x=1100, y=320)

label32 = tk.Label(encryption_frame, text="~",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 15))
label32.place(x=780, y=220)

label33 = tk.Label(encryption_frame, text="*",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 18))
label33.place(x=960, y=270)

label34 = tk.Label(encryption_frame, text="¿",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label34.place(x=830, y=160)

label35 = tk.Label(encryption_frame, text="̈́̒͠",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 17))
label35.place(x=1010, y=400)

label36 = tk.Label(encryption_frame, text="*",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 12))
label36.place(x=700, y=350)

label37 = tk.Label(encryption_frame, text="$",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label37.place(x=720, y=600)

label38 = tk.Label(encryption_frame, text="*̳",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 16))
label38.place(x=1030, y=650)

label39 = tk.Label(encryption_frame, text="]",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 18))
label39.place(x=880, y=700)

label40 = tk.Label(encryption_frame, text="[",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 12))
label40.place(x=920, y=750)

label41 = tk.Label(encryption_frame, text="¿",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 20))
label41.place(x=1100, y=620)

label42 = tk.Label(encryption_frame, text="*̳",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 15))
label42.place(x=780, y=670)

label43 = tk.Label(encryption_frame, text="$",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 18))
label43.place(x=960, y=720)

label44 = tk.Label(encryption_frame, text=":",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 14))
label44.place(x=830, y=770)

label45 = tk.Label(encryption_frame, text="¿",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 17))
label45.place(x=1010, y=780)

label46 = tk.Label(encryption_frame, text="$",
                   fg=var2["fg"], bg=var1["bg"], font=("Arial", 12))
label46.place(x=700, y=790)


# Welcome Label
welcome_label = tk.Label(
    encryption_frame,
    text='''B́̿͘ɪ̈́͌͐ᴏ̀̈́̾C̾́͝ʀ͑́̕ʏ͒̾͑ᴘ͋͌ᴛ̿̓̒''',
    fg=var2["fg"],
    bg=var1["bg"],
    font=("Courier", 90, "bold")

)
# welcome_label.pack(pady=60)
welcome_label.place(x=580, y=100, anchor="center")
min_title = tk.Label(
    encryption_frame,
    text='Personal',
    fg=var2["fg"],
    bg=var1["bg"],
    font=("Courier", 40, "bold")
)
# welcome_label.pack(pady=60)
min_title.place(x=580, y=160, anchor="center")


def open_safe_mail():
    run_safe_mail()


def openFAQ():
    run_FAQ()


def openIPFS():
    run_ipfs()


def openVault():
    run_vault(root)


def on_hover(widget, bg_color):
    widget.bind("<Enter>", lambda e: widget.config(bg=bg_color))
    widget.bind("<Leave>", lambda e: widget.config(bg=var2["fg"]))


# **Fingerprint Scan Button (Centered)**
scan_button = tk.Button(encryption_frame, text="꩜ Scan Fingerprint",
                        relief="flat", bd=0, highlightthickness=0, font=("Courier", 12, "bold"),
                        fg=var1["bg"], bg=var2["fg"], activebackground="#444",
                        cursor="hand2", command=on_scan_button_click)
scan_button.place(x=430, y=350, width=300, height=40)


# **Fingerprint & Key Labels (Centered Below)**
fingerprint_label = tk.Label(encryption_frame, text="👤 Fingerprint ID: None",
                             font=("Courier", 20), bg=var1["bg"], fg=var2["fg"])
fingerprint_label.place(x=430, y=300)

key_label = tk.Label(encryption_frame, text="🔒 Generated Key (SHA-256): None",
                     font=("Courier", 12), bg=var1["bg"], fg=var2["fg"])
key_label.place(x=10000, y=10)

# **Action Frame (Encrypt/Decrypt/File Select)**
action_frame = tk.Frame(encryption_frame, bg=var1["bg"])
action_frame.place(x=430,
                   y=400, width=300, height=120)

action_choice = tk.StringVar(value='encrypt')

encrypt_radio = tk.Radiobutton(action_frame, text="🔐 Encrypt File", variable=action_choice,
                               value='encrypt', font=("Courier", 12), bg=var1["bg"],
                               fg=var2["fg"], selectcolor=var1["bg"], activebackground=var1["bg"])
encrypt_radio.place(x=0, y=10)

decrypt_radio = tk.Radiobutton(action_frame, text="🗝 Decrypt File", variable=action_choice,
                               value='decrypt', font=("Courier", 12), bg=var1["bg"],
                               fg=var2["fg"], selectcolor=var1["bg"], activebackground=var1["bg"])
decrypt_radio.place(x=0, y=40)

file_button = tk.Button(action_frame, text="📂 Select File",
                        relief="flat", bd=0, highlightthickness=0, font=("Courier", 12, "bold"),
                        fg=var1["bg"], bg=var2["fg"], activebackground="#444",
                        cursor="hand2", command=select_file)
file_button.place(x=150, y=14, width=150, height=40)

block = tk.Button(encryption_frame, text="Safe Mail",
                  relief="flat", bd=0, highlightthickness=0, font=("Courier", 12, "bold"),
                  fg=var1["bg"], bg=var2["fg"], activebackground="#444",
                  cursor="hand2", command=open_safe_mail)
block.place(x=430, y=475, width=300, height=40)


# Extendable Sidebar
# Set to False to start with the sidebar hidden
# Extendable Sidebar
# Set to False to start with the sidebar hidden
sidebar_visible = tk.BooleanVar(value=False)


def toggle_sidebar():
    if sidebar_visible.get():
        sidebar_frame.pack_forget()
    else:
        sidebar_frame.pack(side="left", fill="y")
    sidebar_visible.set(not sidebar_visible.get())


sidebar_frame = tk.Frame(encryption_frame, bg=var1["bg"])
# Do not pack the sidebar_frame initially

buttons = [
    ("Safe Mail", open_safe_mail),
    ("The Vault", openVault),
    ("IPFS", openIPFS),
    ("FAQ", openFAQ),
    ("Settings", open_settings),
    ("Exit", root.quit)
]

for text, command in buttons:
    button = tk.Button(sidebar_frame, text=text, command=command, bg=var2["fg"], fg=var1["bg"], font=(
        "Courier", 12), relief="flat", bd=0, highlightthickness=0, width=20, height=2)
    button.pack(fill="x", pady=2)
    on_hover(button, "#555")  # Apply hover effect
    # ...existing code...

toggle_button = tk.Button(encryption_frame, text="☰", command=toggle_sidebar,
                          bg=var2["fg"], fg=var1["bg"], relief="flat", bd=0,
                          highlightthickness=0, font=("Courier", 12), width=1, height=2)
toggle_button.pack(side="top", anchor="nw", pady=10, padx=10)

# No need to call toggle_sidebar() here as the sidebar is already hidden by default

# Define hover effect function


def on_hover(widget, bg_color):
    widget.bind("<Enter>", lambda e: widget.config(bg=bg_color))
    widget.bind("<Leave>", lambda e: widget.config(bg=var2["fg"]))


# Apply hover effect to toggle button
on_hover(toggle_button, "#555")


root.mainloop()
