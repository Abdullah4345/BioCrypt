import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import serial
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import csv
import tkinter.colorchooser as colorchooser
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
import tkinter.colorchooser as colorchooser
from tkinter import ttk
import serial.tools.list_ports
import csv
import sys
import threading


def resource_path(relative_path):
    """ Get the absolute path to a resource, works in development and after PyInstaller packaging. """
    if getattr(sys, 'frozen', False):  
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


selected_value = None
var1 = None
var2 = None


def restart_application():
    """Restarts the application."""
    python = sys.executable
    os.execl(python, python, *sys.argv)


CSV_FILE = "data/theme_settings.csv"


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

    drop_down.set(options[0])

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



CSV_FILE = resource_path('data/theme_settings.csv')


def save_to_csv(var1, var2):
    """ Save data to CSV file. """
    os.makedirs(os.path.dirname(CSV_FILE),
                exist_ok=True)  
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
        return "#ffffff", "#000000"


bg_color, fg_color = read_from_csv()
var1 = {"bg": bg_color}
var2 = {"fg": fg_color}


baud_rate = 9600
arduino_connected = False


def find_arduino_port():
    ports = serial.tools.list_ports.comports()
    for port in ports:
        if "usbmodem" in port.device:
            return port.device
    return None


ARDUINO_PORT = find_arduino_port()
if ARDUINO_PORT:
    try:
        ser = serial.Serial(ARDUINO_PORT, baud_rate, timeout=2)
        arduino_connected = True
        print(f"Connected to Arduino at {ARDUINO_PORT}")
    except serial.SerialException as e:
        print(f"Could not connect to Arduino at {ARDUINO_PORT}: {e}")
else:
    print("No Arduino detected on available ports.")


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


def load_logs():
    """Load encryption and decryption logs from the CSV file into the Treeview."""
    if os.path.isfile(log_file):
        with open(log_file, mode='r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["Operation"] in ["Encrypt", "Decrypt"]:
                    logs_treeview.insert("", "end", values=(
                        row["Timestamp"], row["Operation"], row["Message"]))


def update_log_treeview(message, operation_type="General"):
    """Update the log display in Treeview."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs_treeview.insert("", "end", values=(
        timestamp, operation_type, message))


def hash_fingerprint_id(fingerprint_id):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(str(fingerprint_id).encode('utf-8'))
    return sha256_hash.digest()[:32]


def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))

        iv = cipher.iv
        original_extension = os.path.splitext(file_path)[1].encode('utf-8')
        metadata = original_extension.ljust(BLOCK_SIZE)

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + metadata + ciphertext)

        debug_log(
            f"Encrypted file: {file_path} -> {encrypted_file_path}", operation_type="Encrypt")
        update_log_treeview(
            f"File encrypted: {encrypted_file_path}", operation_type="Encrypt")
        return f"File encrypted successfully: {encrypted_file_path}"
    except Exception as e:
        debug_log(f"Error during encryption: {e}", operation_type="Encrypt")
        update_log_treeview(
            f"Error during encryption: {e}", operation_type="Encrypt")
        return f"Error during encryption: {e}"


def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            iv = f.read(16)
            original_extension = f.read(16).strip().decode('utf-8')
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

        decrypted_file_path = file_path.replace(".enc", original_extension)
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)

        debug_log(
            f"Decrypted file: {file_path} -> {decrypted_file_path}", operation_type="Decrypt")
        update_log_treeview(
            f"File decrypted: {decrypted_file_path}", operation_type="Decrypt")
        return f"File decrypted successfully: {decrypted_file_path}"
    except Exception as e:
        debug_log(f"Error during decryption: {e}", operation_type="Decrypt")
        update_log_treeview(
            f"Error during decryption: {e}", operation_type="Decrypt")
        return f"Error during decryption: {e}"


current_command = None


def send_arduino_command(command):
    global current_command
    current_command = command
    if arduino_connected:
        try:
            ser.write(command.encode('utf-8'))
        except Exception as e:
            debug_log(
                f"Error sending command to Arduino: {e}", operation_type="Error")
    else:
        debug_log(f"Mock command sent: {command}",
                  operation_type="Mock Command")


def read_arduino_data():
    if arduino_connected:
        try:
            return ser.readline().decode('utf-8').strip()
        except Exception as e:
            debug_log(
                f"Error reading from Arduino: {e}", operation_type="Error")
            return None
    else:
        mock_responses = {
            "SCAN": "Found Finger ID #123",
            "ADD": "Fingerprint added successfully.",
        }
        return mock_responses.get(current_command, "")


def on_fingerprint_scan():
    global key
    if not arduino_connected:

        debug_log("Error: Arduino not connected. Cannot scan fingerprint.",
                  operation_type="Error")
        fingerprint_label.config(text="Error: Arduino not connected.")
        key_label.config(text="Generated Key (SHA-256): None")
        return

    debug_log("Sending fingerprint scan command to Arduino.",
              operation_type="Fingerprint Scan")
    send_arduino_command("SCAN")
    check_fingerprint()


def check_fingerprint():
    data = read_arduino_data()
    debug_log(f"Received data: {data}", operation_type="Fingerprint Scan")
    if "Found Finger ID" in data:
        fingerprint_id = int(data.split('#')[1].split()[0])
        global key
        key = hash_fingerprint_id(fingerprint_id)
        key_hex = hashlib.sha256(key).hexdigest()
        fingerprint_label.config(text=f"Fingerprint ID: {fingerprint_id}")
        key_label.config(text=f"Generated Key (SHA-256): {key_hex}")
        action_frame.pack(pady=20)
    elif "Fingerprint not found" in data:
        fingerprint_label.config(text="Fingerprint not found. Try again.")
        debug_log("Fingerprint not found. Waiting for retry...",
                  operation_type="Fingerprint Scan")
        root.after(100, check_fingerprint)
    elif data:
        debug_log(f"Unexpected data: {data}. Retrying...",
                  operation_type="Fingerprint Scan")
        root.after(100, check_fingerprint)
    else:
        debug_log("Empty response. Retrying...",
                  operation_type="Fingerprint Scan")
        root.after(100, check_fingerprint)


def select_file():
    file_path = filedialog.askopenfilename(title="Select a file")
    if file_path:
        action_result = encrypt_file(file_path, key) if action_choice.get(
        ) == 'encrypt' else decrypt_file(file_path, key)
        messagebox.showinfo(
            f"{action_choice.get().capitalize()}ion Result", action_result)


def on_add_fingerprint():
    debug_log("Sending add fingerprint command.",
              operation_type="Add Fingerprint")
    send_arduino_command("ADD")
    add_status_label.config(text="Sending add fingerprint command...")
    mini_terminal.delete(1.0, tk.END)
    check_add_fingerprint()


def check_add_fingerprint():
    data = read_arduino_data()
    debug_log(f"Received data: {data}", operation_type="Add Fingerprint")
    mini_terminal.insert(tk.END, f"Received data: {data}\n")
    mini_terminal.yview(tk.END)

    if "Place finger" in data:
        add_status_label.config(text="Place your finger on the scanner...")
        mini_terminal.insert(tk.END, "Place your finger on the scanner...\n")
    elif "Remove finger" in data:
        add_status_label.config(text="Remove your finger and wait...")
        mini_terminal.insert(tk.END, "Remove your finger and wait...\n")
    elif "Fingerprint added" in data:
        try:
            fingerprint_id = data.split('#')[1].split()[0]
            add_status_label.config(
                text=f"Fingerprint added successfully! ID: {fingerprint_id}")
            save_log([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "Add Fingerprint", f"Added fingerprint ID: {fingerprint_id}"])
            update_log_treeview(
                f"Fingerprint added: {fingerprint_id}", operation_type="Add Fingerprint")
            mini_terminal.insert(
                tk.END, f"Fingerprint added successfully: ID {fingerprint_id}\n")
        except IndexError:
            debug_log(
                f"Error parsing fingerprint ID from data: {data}", operation_type="Add Fingerprint")
            mini_terminal.insert(
                tk.END, "Error parsing fingerprint ID. Data format unexpected.\n")
            add_status_label.config(
                text="Error adding fingerprint. Try again.")
    elif "Error" in data:
        add_status_label.config(text="Error adding fingerprint. Try again.")
        mini_terminal.insert(tk.END, "Error adding fingerprint. Try again.\n")
    else:
        debug_log("Waiting for more fingerprint data...",
                  operation_type="Add Fingerprint")
        root.after(100, check_add_fingerprint)


# GUI Setup
root = tk.Tk()
root.title("BioCrypt")
root.geometry("1200x700")
root.resizable(False, False)

root.configure(bg=var1["bg"])



notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)


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



welcome_label = tk.Label(
    encryption_frame,
    text='BioCrypt',
    fg=var2["fg"],
    bg=var1["bg"],
    font=("Courier", 90, "bold")
)

welcome_label.place(x=580, y=100, anchor="center")


def open_vault():
    """Function to run the vault.py program in a separate thread."""
    def run_program():
        os.system("python3 vault.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_cloud():
    """Function to run the vault.py program in a separate thread."""
    def run_program():
        os.system("python3 cloud.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_IPFS():
    """Function to run the IPFS program in a separate thread."""
    def run_program():
        os.system("python3 ipfs.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_time_lock():
    """Function to run the Time Lock program in a separate thread."""
    def run_program():
        os.system("python3 time_lock.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_file_beam():
    """Function to run the File Beam program in a separate thread."""
    def run_program():
        os.system("python3 file_beam.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_safe_mail():
    """Function to run the Safe Mail program in a separate thread."""
    def run_program():
        os.system("python3 safe_mail.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_compress():
    """Function to run the Compress Files program in a separate thread."""
    def run_program():
        os.system("python3 compress.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_summary():
    """Function to run the Summaries program in a separate thread."""
    def run_program():
        os.system("python3 summary.py")

    threading.Thread(target=run_program, daemon=True).start()


def open_assistant():
    """Function to run the Assistant program in a separate thread."""
    def run_program():
        os.system("python3 assistant.py")

    threading.Thread(target=run_program, daemon=True).start()



def on_hover(widget, bg_color):
    widget.bind("<Enter>", lambda e: widget.config(bg=bg_color))
    widget.bind("<Leave>", lambda e: widget.config(bg=var2["fg"]))


scan_button = tk.Button(encryption_frame, text="꩜ Scan Fingerprint",
                        relief="flat", bd=0, highlightthickness=0, font=("Courier", 12, "bold"),
                        fg=var1["bg"], bg=var2["fg"], activebackground="#444",
                        cursor="hand2", command=on_fingerprint_scan)
scan_button.place(x=430, y=350, width=300, height=40)


fingerprint_label = tk.Label(encryption_frame, text="👤 Fingerprint ID: None",
                             font=("Courier", 20), bg=var1["bg"], fg=var2["fg"])
fingerprint_label.place(x=430, y=300)

key_label = tk.Label(encryption_frame, text="🔒 Generated Key (SHA-256): None",
                     font=("Courier", 12), bg=var1["bg"], fg=var2["fg"])
key_label.place(x=10000, y=10)

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

block = tk.Button(encryption_frame, text="IPFS",
                  relief="flat", bd=0, highlightthickness=0, font=("Courier", 12, "bold"),
                  fg=var1["bg"], bg=var2["fg"], activebackground="#444",
                  cursor="hand2", command=open_IPFS)
block.place(x=430, y=475, width=300, height=40)

sidebar_visible = tk.BooleanVar(value=False)


def toggle_sidebar():
    if sidebar_visible.get():
        sidebar_frame.pack_forget()
    else:
        sidebar_frame.pack(side="left", fill="y")
    sidebar_visible.set(not sidebar_visible.get())


sidebar_frame = tk.Frame(encryption_frame, bg=var1["bg"])


buttons = [
    ("The Vault", open_vault),
    ("Cloud", open_cloud),
    ("IPFS", open_IPFS),
    ("Time Lock", open_time_lock),
    ("File Beam", open_file_beam),
    ("Safe Mail", open_safe_mail),
    ("Compress Files", open_compress),
    ("Summaries", open_summary),
    ("Assistant", open_assistant),
    ("Settings", open_settings),


]

for text, command in buttons:
    button = tk.Button(sidebar_frame, text=text, command=command, bg=var2["fg"], fg=var1["bg"], font=(
        "Courier", 12), relief="flat", bd=0, highlightthickness=0, width=20, height=2)
    button.pack(fill="x", pady=2)
    on_hover(button, "#555")  


toggle_button = tk.Button(encryption_frame, text="☰", command=toggle_sidebar,
                          bg=var2["fg"], fg=var1["bg"], relief="flat", bd=0,
                          highlightthickness=0, font=("Courier", 12), width=1, height=2)
toggle_button.pack(side="top", anchor="nw", pady=10, padx=10)


def on_hover(widget, bg_color):
    widget.bind("<Enter>", lambda e: widget.config(bg=bg_color))
    widget.bind("<Leave>", lambda e: widget.config(bg=var2["fg"]))



on_hover(toggle_button, "#555")


# Tab 2: Add Fingerprint
add_fingerprint_frame = tk.Frame(notebook, bg=var1["bg"])
notebook.add(add_fingerprint_frame, text="Add Fingerprint")

add_fingerprint_label = tk.Label(add_fingerprint_frame, text="Place your finger on the scanner",
                                 bg=var1["bg"], fg=var2["fg"], font=("Courier", 20, "bold"))
add_fingerprint_label.pack(pady=70)

add_button = tk.Button(add_fingerprint_frame, text="Add Fingerprint", command=on_add_fingerprint,
                       relief="flat", bd=0, highlightthickness=0, bg=var2["fg"], fg=var1["bg"], font=("Courier", 12), width=20, height=2)
add_button.pack(pady=50)

add_status_label = tk.Label(add_fingerprint_frame, text="Status: Waiting for command...",
                            bg=var1["bg"], fg=var2["fg"], font=("Courier", 14))
add_status_label.pack()


mini_terminal = tk.Text(add_fingerprint_frame,
                        height=50, width=160, bg=var2["fg"])
mini_terminal.pack(pady=10)

# Tab 3: Logs
log_frame = tk.Frame(notebook, bg=var1["bg"])
notebook.add(log_frame, text="Logs")

logs_treeview = ttk.Treeview(log_frame, columns=(
    "Timestamp", "Operation", "Message"), show="headings", style="Custom.Treeview")
logs_treeview.heading("Timestamp", text="Timestamp")
logs_treeview.heading("Operation", text="Operation")
logs_treeview.heading("Message", text="Message")

logs_treeview.column("Timestamp", width=3)
logs_treeview.column("Operation", width=3)
logs_treeview.column("Message", width=600)

logs_treeview.pack(fill="both", expand=True)
load_logs()


style = ttk.Style()
style.configure("Custom.Treeview",
                background=var1["bg"], foreground=var2["fg"], fieldbackground=var1["bg"])
style.configure("Custom.Treeview.Heading",
                background=var1["bg"], foreground=var2["fg"])

root.mainloop()
