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


IPFS_GATEWAY_URL = "https://ipfs.io"  


IPFS_API_URL = "http://127.0.0.1:5001/api/v0"


def upload_to_ipfs(file_path):
    with open(file_path, "rb") as file:
        response = requests.post(f"{IPFS_API_URL}/add", files={"file": file})
        return response.json()["Hash"] if response.status_code == 200 else None



INFURA_URL = ""
CONTRACT_ADDRESS = ""
ACCOUNT_ADDRESS = ""
PRIVATE_KEY = ""
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


w3 = web3.Web3(web3.HTTPProvider(INFURA_URL))
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=YOUR_CONTRACT_ABI)


KEYS_FILE = "data/encryption_keys.json"


def save_encryption_key(cid, key):
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            keys = json.load(f)
    else:
        keys = {}

    keys[cid] = key.hex()

    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f)


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


def upload_to_ipfs(file_path):
    with open(file_path, "rb") as file:
        response = requests.post(f"{IPFS_API_URL}/add", files={"file": file})
        if response.status_code == 200:

            return response.json()["Hash"]

        else:
            print(f"❌ IPFS upload failed: {response.text}")
            return None


def store_cid_on_blockchain(cid):
    nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS)
    print(f"Using nonce: {nonce}")

    txn = contract.functions.storeFileCID(cid).build_transaction({
        "from": ACCOUNT_ADDRESS,
        "nonce": nonce,
        "gas": 100000,  
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


def save_file_name(cid, file_name):
    FILE_NAMES_FILE = "data/file_names.json"
    if os.path.exists(FILE_NAMES_FILE):
        with open(FILE_NAMES_FILE, "r") as f:
            file_names = json.load(f)
    else:
        file_names = {}

    file_names[cid] = file_name

    with open(FILE_NAMES_FILE, "w") as f:
        json.dump(file_names, f)


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


    cid = upload_to_ipfs(encrypted_file)
    if not cid:
        messagebox.showerror("Error", "Failed to upload file to IPFS.")
        return

    save_encryption_key(cid, encryption_key)
    save_file_name(cid, file_name)  

    tx_hash = store_cid_on_blockchain(cid)

    os.remove(encrypted_file)

    messagebox.showinfo(
        "Success", f"File uploaded! CID: {cid}\nTx Hash: {tx_hash}")


def list_stored_files():
    print("Contract Address:", contract.address)
    cids = contract.functions.getStoredCIDs().call()
    print("Stored CIDs in contract:", cids)

 
    try:
        with open("data/file_names.json", "r") as f:
            file_names = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        file_names = {}

    print("Fetching stored files...") 
    cids = contract.functions.getStoredCIDs().call()
    print("Received CIDs:", cids) 
    file_listbox.config(state=tk.NORMAL)
    file_listbox.delete(0, tk.END) 

    for cid in cids:
        
        display_name = file_names.get(cid, cid)
        file_listbox.insert(tk.END, display_name)
    print("List updated successfully!")  



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
    backoff = 5  
    for attempt in range(max_attempts):
        for gateway in IPFS_GATEWAYS:
            url = f"{gateway}{cid}"
            print(f"Trying {url} (Attempt {attempt + 1})")

            try:
                response = requests.get(url, timeout=60)  
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
            backoff *= 2  

    print("❌ All retrieval attempts failed.")
    return None


def retrieve_and_decrypt():
    selected = file_listbox.curselection()
    if not selected:
        messagebox.showwarning("Warning", "Select a file to retrieve!")
        return

    display_name = file_listbox.get(selected[0]) 

    
    try:
        with open("data/file_names.json", "r") as f:
            file_names = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        messagebox.showerror("Error", "File names file missing or corrupted!")
        return

    
    cid = None
    for key, value in file_names.items():
        if value == display_name:
            cid = key
            break  

    if not cid:
        messagebox.showerror("Error", "CID not found for the selected file!")
        return

    
    if not authenticate_touch_id():
        messagebox.showerror("Error", "Authentication Failed!")
        return

    file_data = retrieve_file_with_retry(cid)

    if file_data is None:
        messagebox.showerror("Error", "Failed to retrieve file from IPFS!")
        return

    
    try:
        with open("data/encryption_keys.json", "r") as key_file:
            encryption_keys = json.load(key_file)
    except (FileNotFoundError, json.JSONDecodeError):
        messagebox.showerror(
            "Error", "Encryption keys file missing or corrupted!")
        return

    
    encryption_key = encryption_keys.get(cid)

    if not encryption_key:
        messagebox.showerror("Error", "No encryption key found for this file!")
        return

    encryption_key = bytes.fromhex(encryption_key)

    
    iv = file_data[:16] 
    ciphertext = file_data[16:]  

    try:
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError):
        messagebox.showerror(
            "Error", "Decryption failed! Invalid key or corrupted file.")
        return

   
    root = tk.Tk()
    root.withdraw()  

    save_path = filedialog.asksaveasfilename(
        defaultextension="",
        initialfile="DecryptedFile",
        title="Save Decrypted File",
        filetypes=[("All Files", "*.*")]
    )

    if save_path:  
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
