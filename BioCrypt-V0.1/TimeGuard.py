import os
import sqlite3
import uuid
import hashlib
import secrets
import string
from datetime import datetime
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import font as tkfont
import logging
from tkcalendar import Calendar

logging.basicConfig(
    filename='data/timeguard.log',
    level=logging.DEBUG,  # Use DEBUG level for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class TimeGuardVault:
    def __init__(self, storage_dir='data/vault_storage', db_path='data/timeguard.db'):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self.db_path = db_path
        self.lock = threading.Lock()
        self.running = True
        
        # Generate fixed encryption key
        self.fernet = Fernet(Fernet.generate_key())
        
        self.conn = self._create_connection()
        self._init_db()
        
        self.cleanup_thread = threading.Thread(target=self._auto_cleanup, daemon=True)
        self.cleanup_thread.start()

    def _create_connection(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self.lock:
            conn = self._create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    encrypted_path TEXT,
                    creation_time REAL NOT NULL,
                    expiration_time REAL NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    attempts_left INTEGER NOT NULL,
                    otp_hash TEXT NOT NULL,
                    deleted_hash TEXT,
                    email TEXT NOT NULL
                )
            ''')
            conn.commit()
            conn.close()

    def _generate_otp(self, length=8):
        chars = string.digits + string.ascii_uppercase
        return ''.join(secrets.choice(chars) for _ in range(length))

    def _auto_cleanup(self):
        while self.running:
            self.check_expirations()
            threading.Event().wait(60)

    def check_expirations(self):
        """Check and delete expired files."""
        now = datetime.now().timestamp()
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id, encrypted_path 
                FROM files 
                WHERE deleted_hash IS NULL AND expiration_time <= ?
            ''', (now,))
            rows = cursor.fetchall()

            for row in rows:
                file_id, encrypted_path = row
                self._delete_file(file_id, encrypted_path, "Expiration time reached")

    def _delete_file(self, file_id, encrypted_path, reason):
        """Delete a file and log the reason."""
        try:
            if os.path.exists(encrypted_path):
                with open(encrypted_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                os.remove(encrypted_path)
            else:
                file_hash = "File not found during deletion"
        except Exception as e:
            file_hash = f"Error during deletion: {str(e)}"

        logging.info(f"File {file_id} deleted. Reason: {reason}")

        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                UPDATE files 
                SET deleted_hash = ?, 
                    encrypted_path = NULL,
                    attempts_left = 0 
                WHERE id = ?
            ''', (file_hash, file_id))
            self.conn.commit()

    def add_file(self, file_path, expiration_datetime, email, max_attempts=3):
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = self.fernet.encrypt(data)
        file_id = str(uuid.uuid4())
        encrypted_path = os.path.join(self.storage_dir, f"{file_id}.enc")
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Generate and store OTP
        otp = self._generate_otp()  # Generates a 6-digit code
        otp_hash = hashlib.sha256(otp.encode()).hexdigest()  # Hash the OTP for storage
        
        creation_time = datetime.now().timestamp()
        expiration_time = expiration_datetime.timestamp()
        with self.lock:
            conn = self._create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (file_id, os.path.basename(file_path), encrypted_path,
                creation_time, expiration_time, max_attempts, max_attempts,
                otp_hash, None, email))
            conn.commit()
            conn.close()
        
        return file_id, otp  # Return the plaintext OTP

    def access_file(self, file_id):
        """
        Retrieve a file without requiring an OTP.
        """
        with self.lock:  # Ensure thread safety
            conn = self._create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM files 
                WHERE id = ? AND deleted_hash IS NULL
            ''', (file_id,))
            row = cursor.fetchone()
            
            if not row:
                conn.close()
                logging.error(f"File not found or already deleted: {file_id}")
                raise ValueError("File not found or already deleted")
            
            file_info = {
                'id': row[0],
                'encrypted_path': row[2],
                'attempts_left': row[6],
                'max_attempts': row[5],
                'email': row[9]
            }

            # Reset attempts on successful access
            cursor.execute('''
                UPDATE files SET attempts_left = ?
                WHERE id = ?
            ''', (file_info['max_attempts'], file_id))
            conn.commit()
            conn.close()
            
            # Decrypt and return the file
            with open(file_info['encrypted_path'], 'rb') as f:
                encrypted_data = f.read()
            
            logging.info(f"File accessed successfully: {file_id}")
            return self.fernet.decrypt(encrypted_data), row[1], file_info['email']  # Return decrypted data, original name, and email

    def delete_file(self, file_id):
        """
        Delete a file from the vault.
        """
        with self.lock:
            conn = self._create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT encrypted_path FROM files WHERE id = ?
            ''', (file_id,))
            row = cursor.fetchone()
            if row:
                encrypted_path = row[0]
                if os.path.exists(encrypted_path):
                    os.remove(encrypted_path)
                cursor.execute('''
                    DELETE FROM files WHERE id = ?
                ''', (file_id,))
                conn.commit()
            conn.close()
            logging.info(f"File {file_id} deleted due to maximum attempts reached.")

    def close(self):
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join()
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

class ModernGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TimeGuard 2.0")
        self.geometry("1000x700")
        self.configure(bg='#f0f0f0')
        
        # Custom font setup
        self.title_font = tkfont.Font(family='Helvetica', size=18, weight='bold')
        self.text_font = tkfont.Font(family='Arial', size=12)
        
        # Initialize vault
        self.vault = TimeGuardVault()
        
        # Setup UI
        self._setup_main_container()
        self._create_file_management_tab()
        self._create_access_tab()
        self._create_status_bar()
        
        # Center window
        self.eval('tk::PlaceWindow . center')
        
    def _retrieve_file(self, file_id):
        try:
            # Access the file from the vault
            data, name, email = self.vault.access_file(file_id)
            
            # Generate a new OTP
            otp = self.vault._generate_otp()
            otp_hash = hashlib.sha256(otp.encode()).hexdigest()
            
            # Update the OTP hash in the database
            with self.vault.lock:
                conn = self.vault._create_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE files SET otp_hash = ? WHERE id = ?
                ''', (otp_hash, file_id))
                conn.commit()
                conn.close()
            
            # Send OTP to email
            self._send_otp_email(email, otp)
            
            # Show OTP verification dialog
            self.after(0, lambda: self._show_otp_verification_dialog_for_access(file_id, otp_hash))
        
        except ValueError as e:
            # Handle file not found or already deleted
            messagebox.showerror("Error", str(e))
        
        except Exception as e:
            # Handle unexpected errors
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
            logging.error(f"Unexpected error during file access: {str(e)}")
        
    

    def _setup_main_container(self):
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Notebook (Tabbed interface)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

    def _create_file_management_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Manage Files")
        
        # File Input Section
        input_frame = ttk.LabelFrame(tab, text="Secure File Upload")
        input_frame.pack(fill=tk.X, pady=10, padx=10)
        
        ttk.Button(input_frame, text="Select File", command=self._browse_file, 
                  style='Accent.TButton').grid(row=0, column=0, padx=5, pady=5)
        self.file_path = ttk.Entry(input_frame, width=50, font=self.text_font)
        self.file_path.grid(row=0, column=1, padx=5, pady=5)
        
        # Settings
        settings_frame = ttk.LabelFrame(tab, text="File Settings")
        settings_frame.pack(fill=tk.X, pady=10, padx=10)
        
        # Expiration Date Label
        ttk.Label(settings_frame, text="Expiration Date:", font=self.text_font).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        
        # Calendar Section
        self.calendar = Calendar(settings_frame, selectmode='day', date_pattern='y-mm-dd', 
                                 font=self.text_font, background='teal', foreground='white', 
                                 selectbackground='teal', selectforeground='white')
        self.calendar.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        # Time Section
        ttk.Button(settings_frame, text="Set Time", command=self._show_time_picker).grid(row=2, column=0, padx=10, pady=5, sticky="w")
        
        self.time_frame = ttk.Frame(settings_frame)
        self.time_frame.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.time_frame.grid_remove()  # Initially hide the time frame
        
        ttk.Label(self.time_frame, text="Hour:", font=self.text_font).grid(row=0, column=0, sticky="w", padx=5)
        self.hour_spinbox = ttk.Spinbox(self.time_frame, from_=0, to=23, font=self.text_font, width=5)
        self.hour_spinbox.grid(row=0, column=1, padx=5)
        
        ttk.Label(self.time_frame, text="Minute:", font=self.text_font).grid(row=0, column=2, sticky="w", padx=5)
        self.minute_spinbox = ttk.Spinbox(self.time_frame, from_=0, to=59, font=self.text_font, width=5)
        self.minute_spinbox.grid(row=0, column=3, padx=5)
        
        ttk.Label(self.time_frame, text="Second:", font=self.text_font).grid(row=0, column=4, sticky="w", padx=5)
        self.second_spinbox = ttk.Spinbox(self.time_frame, from_=0, to=59, font=self.text_font, width=5)
        self.second_spinbox.grid(row=0, column=5, padx=5)
        
        # Add space between Set Time and Max Attempts
        ttk.Label(settings_frame, text="").grid(row=4, column=0, pady=10)
        
        # Max Attempts Section
        ttk.Label(settings_frame, text="Max Access Attempts:", font=self.text_font).grid(row=5, column=0, sticky="w", padx=10, pady=5)
        self.max_attempts = ttk.Spinbox(settings_frame, from_=1, to=10, font=self.text_font)
        self.max_attempts.grid(row=5, column=1, padx=10, pady=5, sticky="w")
        
        # Action Button
        ttk.Button(tab, text="Secure My File", command=self._add_file_threaded,
                  style='Accent.TButton').pack(pady=20)

    def _show_time_picker(self):
        self.time_frame.grid()

    def _create_access_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Access Files")
        
        # Main container for the tab
        main_frame = ttk.Frame(tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # File List Section
        list_frame = ttk.LabelFrame(main_frame, text="Secured Files")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Treeview with scrollbar
        self.file_tree = ttk.Treeview(list_frame, columns=("ID", "Name", "Created", "Expires", "Attempts"), 
                                    show="headings", selectmode="browse")
        
        # Configure columns
        columns = [
            ("ID", "File ID", 220),
            ("Name", "Original Name", 180),
            ("Created", "Created At", 150),
            ("Expires", "Expires At", 150),
            ("Attempts", "Attempts Left", 100)
        ]
        
        for col_id, heading, width in columns:
            self.file_tree.heading(col_id, text=heading, anchor=tk.W)
            self.file_tree.column(col_id, width=width, anchor=tk.W, stretch=True)  # Corrected line

        # Add scrollbar
        scroll_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scroll_y.set)
        
        # Grid layout for proper resizing
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)

        # Context menu
        self.tree_menu = tk.Menu(self, tearoff=0)
        self.tree_menu.add_command(label="Copy File ID", command=self._copy_file_id)
        self.tree_menu.add_command(label="Copy OTP", command=self._copy_otp)
        self.file_tree.bind("<Button-3>", self._show_tree_menu)

        # Control buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=5)
        
        ttk.Button(btn_frame, text="Refresh", command=self._refresh_file_list,
                style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Search", command=self._toggle_search,
                style='Accent.TButton').pack(side=tk.LEFT, padx=5)

        # Search entry
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(main_frame, textvariable=self.search_var, 
                                    font=self.text_font)
        self.search_entry.pack_forget()
        self.search_var.trace_add("write", self._perform_search)

        # File Access Section
        access_frame = ttk.LabelFrame(main_frame, text="File Access")
        access_frame.pack(fill=tk.X, pady=10)

        # Input fields grid
        ttk.Label(access_frame, text="File ID:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.file_id_entry = ttk.Entry(access_frame, font=self.text_font)
        self.file_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Button(access_frame, text="Retrieve File", command=self._access_file_threaded,
                style='Accent.TButton').grid(row=1, column=1, pady=10, sticky="e")
        
        access_frame.grid_columnconfigure(1, weight=1)

        # Initial population
        self._refresh_file_list()

    def _refresh_file_list(self):
        """Refresh the file list with updated database information."""
        try:
            # Clear current selection and items
            self.file_tree.selection_remove(self.file_tree.selection())
            self.file_tree.delete(*self.file_tree.get_children())

            # Fetch active files
            with self.vault.lock:
                cursor = self.vault.conn.cursor()
                cursor.execute('''
                    SELECT id, original_name, creation_time, expiration_time, attempts_left 
                    FROM files 
                    WHERE deleted_hash IS NULL
                    ORDER BY creation_time DESC
                ''')
                rows = cursor.fetchall()

            # Populate the treeview
            for row in rows:
                file_id, name, creation_time, expiration_time, attempts = row
                try:
                    # Validate timestamps
                    created = datetime.fromtimestamp(creation_time).strftime("%Y-%m-%d %H:%M")
                    expires = datetime.fromtimestamp(expiration_time).strftime("%Y-%m-%d %H:%M")

                    # Check if the file has expired
                    if expiration_time <= datetime.now().timestamp():
                        # Delete the expired file
                        self.vault._delete_file(file_id, os.path.join(self.vault.storage_dir, f"{file_id}.enc"), "Expiration time reached")
                        continue  # Skip adding expired files to the list

                    self.file_tree.insert("", "end", values=(
                        file_id,
                        name,
                        created,
                        expires,
                        f"{attempts} left"
                    ))
                except (OSError, ValueError) as e:
                    # Skip files with invalid timestamps
                    logging.error(f"Invalid timestamp for file {file_id}: {e}")
                    continue

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to load files:\n{str(e)}")

    def _show_tree_menu(self, event):
        """Show context menu for treeview items"""
        item = self.file_tree.identify_row(event.y)
        if item:
            self.file_tree.selection_set(item)
            self.tree_menu.tk_popup(event.x_root, event.y_root)

    def _copy_file_id(self):
        """Copy selected file ID to clipboard"""
        selected = self.file_tree.selection()
        if selected:
            file_id = self.file_tree.item(selected[0], "values")[0]
            self.clipboard_clear()
            self.clipboard_append(file_id)

    def _toggle_search(self):
        """Toggle visibility of search box"""
        if self.search_entry.winfo_ismapped():
            self.search_entry.pack_forget()
            self.search_var.set("")
        else:
            self.search_entry.pack(fill=tk.X, pady=5)
            self.search_entry.focus()

    def _perform_search(self, *args):
        """Filter treeview items based on search query"""
        query = self.search_var.get().lower()
        for item in self.file_tree.get_children():
            values = [str(v).lower() for v in self.file_tree.item(item, "values")]
            if any(query in v for v in values):
                self.file_tree.attach(item, "", "end")  # Reattach matching items
            else:
                self.file_tree.detach(item)  # Hide non-matching items

    def _create_status_bar(self):
        self.status = ttk.Label(self.main_container, text="Ready", 
                              relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def _browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_path.delete(0, tk.END)
        self.file_path.insert(0, filename)

    def _show_email_dialog(self, callback):
        dialog = tk.Toplevel(self)
        dialog.title("Enter Email")
        dialog.geometry("400x150")
        
        ttk.Label(dialog, text="Enter your email to receive the OTP:", font=self.text_font).pack(pady=10)
        self.email_entry = ttk.Entry(dialog, font=self.text_font, width=30)
        self.email_entry.pack(pady=10)
        
        ttk.Button(dialog, text="Submit", command=lambda: self._on_email_submit(dialog, callback)).pack(pady=10)

    def _on_email_submit(self, dialog, callback):
        email = self.email_entry.get()
        if not email or "@" not in email:
            messagebox.showerror("Error", "Please enter a valid email address.")
            return
        self.email = email  # Store the email for later use
        dialog.destroy()
        callback(email)

    def _send_otp_email(self, email, otp):
        try:
            sender_email = "biocryptprogram@gmail.com"
            sender_password = "nwxv ztza szsi trcx"
            smtp_server = "smtp.gmail.com"
            smtp_port = 587

            if not sender_email or not sender_password:
                raise ValueError("Email credentials not configured")

            msg = MIMEText(f"Your TimeGuard OTP is: {otp}\n\nFile will auto-delete after expiration.")
            msg['Subject'] = "Your Secure Access Code"
            msg['From'] = sender_email
            msg['To'] = email

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, email, msg.as_string())

            messagebox.showinfo("Success", f"OTP sent to {email}")
        except Exception as e:
            error_msg = (
                f"Failed to send OTP: {str(e)}\n\n"
                "Troubleshooting Steps:\n"
                "1. Use a Gmail account with 2-Step Verification enabled\n"
                "2. Generate an App Password for your email\n"
                "3. Ensure you're using the App Password (16-digit code)\n"
                "4. Check your internet connection"
            )
            self.after(0, lambda e=e: messagebox.showerror("Email Error", error_msg))

    def _show_otp_verification_dialog(self, otp, callback):
        dialog = tk.Toplevel(self)
        dialog.title("Verify OTP")
        dialog.geometry("400x150")
        
        ttk.Label(dialog, text="Enter the OTP sent to your email:", font=self.text_font).pack(pady=10)
        self.otp_verify_entry = ttk.Entry(dialog, font=self.text_font, width=30)
        self.otp_verify_entry.pack(pady=10)
        
        ttk.Button(dialog, text="Verify", command=lambda: self._on_otp_verify(dialog, otp, callback)).pack(pady=10)

    def _on_otp_verify(self, dialog, otp, callback):
        user_otp = self.otp_verify_entry.get()
        if user_otp == otp:
            dialog.destroy()
            callback()
        else:
            self.max_attempts -= 1
            if self.max_attempts <= 0:
                messagebox.showerror("Error", "Maximum attempts reached. Access denied.")
                self.vault._delete_file(self.file_id, self.encrypted_path, "Maximum attempts reached")
                dialog.destroy()
            else:
                messagebox.showerror("Error", f"Invalid OTP. {self.max_attempts} attempts left.")

    def _copy_otp(self):
        """Copy OTP for the selected file to clipboard"""
        selected = self.file_tree.selection()
        if selected:
            file_id = self.file_tree.item(selected[0], "values")[0]
            try:
                with self.vault.lock:
                    conn = self.vault._create_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT otp_hash FROM files WHERE id = ?
                    ''', (file_id,))
                    row = cursor.fetchone()
                    conn.close()
                
                if row and row[0]:
                    self.clipboard_clear()
                    self.clipboard_append(row[0])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to retrieve OTP: {str(e)}")

    def _add_file_threaded(self):
        def add_task():
            try:
                file_path = self.file_path.get()
                max_attempts = int(self.max_attempts.get())
                
                if not os.path.exists(file_path):
                    self.after(0, lambda: messagebox.showerror("Error", "File not found!"))
                    return
                
                # Show email dialog
                self.after(0, lambda: self._show_email_dialog(lambda email: self._process_file(email, file_path, max_attempts)))
                
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=add_task, daemon=True).start()

    def _process_file(self, email, file_path, max_attempts):
        try:
            # Generate OTP
            otp = self.vault._generate_otp()
            
            # Send OTP to email
            self._send_otp_email(email, otp)
            
            # Show OTP verification dialog
            self.after(0, lambda: self._show_otp_verification_dialog(otp, lambda: self._secure_file(file_path, max_attempts, otp)))
        
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error", str(e)))

    def _secure_file(self, file_path, max_attempts, otp):
        try:
            expiration_date = self.calendar.get_date()
            expiration_time = f"{self.hour_spinbox.get()}:{self.minute_spinbox.get()}:{self.second_spinbox.get()}"
            expiration_datetime = datetime.strptime(f"{expiration_date} {expiration_time}", "%Y-%m-%d %H:%M:%S")
            file_id, _ = self.vault.add_file(file_path, expiration_datetime, self.email, max_attempts)
            self.after(0, lambda: self.status.config(text="File secured successfully!"))
            self.after(0, lambda: self._show_passcode_dialog(file_id, otp))
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error", str(e)))

    def _show_passcode_dialog(self, file_id, otp):
        dialog = tk.Toplevel(self)
        dialog.title("File Secured")
        dialog.geometry("400x200")
        
        ttk.Label(dialog, text="Your file has been secured!", font=self.title_font).pack(pady=10)
        ttk.Label(dialog, text=f"File ID: {file_id}", font=self.text_font).pack(pady=5)
        ttk.Label(dialog, text=f"Access Code: {otp}", font=self.text_font).pack(pady=5)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

    def _access_file_threaded(self):
        def access_task():
            try:
                file_id = self.file_id_entry.get()
                
                if not file_id:
                    self.after(0, lambda: messagebox.showwarning("Input Error", "Please provide a File ID"))
                    return
                
                # Retrieve the file and send OTP
                self.after(0, lambda: self._retrieve_file(file_id))
            
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}"))
                logging.error(f"Unexpected error during file access: {str(e)}")
        
        threading.Thread(target=access_task, daemon=True).start()

    def _show_otp_verification_dialog_for_access(self, file_id, otp_hash):
        dialog = tk.Toplevel(self)
        dialog.title("Verify OTP")
        dialog.geometry("400x150")
        
        ttk.Label(dialog, text="Enter the OTP sent to your email:", font=self.text_font).pack(pady=10)
        self.otp_verify_entry_access = ttk.Entry(dialog, font=self.text_font, width=30)
        self.otp_verify_entry_access.pack(pady=10)
        
        ttk.Button(dialog, text="Verify", command=lambda: self._on_otp_verify_for_access(dialog, file_id, otp_hash)).pack(pady=10)

    def _on_otp_verify_for_access(self, dialog, file_id, otp_hash):
        user_otp = self.otp_verify_entry_access.get()
        user_otp_hash = hashlib.sha256(user_otp.encode()).hexdigest()  # Hash the user-provided OTP
        
        if user_otp_hash == otp_hash:  # Compare hashes
            dialog.destroy()
            self._retrieve_file_data(file_id)  # Call the _retrieve_file_data method
        else:
            # Fetch the current attempts left from the database
            with self.vault.lock:
                conn = self.vault._create_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT attempts_left FROM files WHERE id = ?
                ''', (file_id,))
                row = cursor.fetchone()
                conn.close()
            
            if row:
                attempts_left = row[0] - 1  # Decrement attempts left
                if attempts_left <= 0:
                    messagebox.showerror("Error", "Maximum attempts reached. Access denied.")
                    self.vault.delete_file(file_id)  # Delete the file from the vault
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", f"Invalid OTP. {attempts_left} attempts left.")
                    with self.vault.lock:
                        conn = self.vault._create_connection()
                        cursor = conn.cursor()
                        cursor.execute('''
                            UPDATE files SET attempts_left = ? WHERE id = ?
                        ''', (attempts_left, file_id))
                        conn.commit()
                        conn.close()

    def _retrieve_file_data(self, file_id):
        try:
            # Access the file from the vault
            data, name, _ = self.vault.access_file(file_id)
            
            # Ask the user where to save the file
            save_path = filedialog.asksaveasfilename(
                initialfile=name,  # Suggest the original file name
                defaultextension=".*",  # Use the original file extension
                filetypes=[("All Files", "*.*")]  # Allow all file types
            )
            
            if save_path:
                # Write the decrypted data to the selected file
                with open(save_path, 'wb') as f:
                    f.write(data)
                
                # Notify the user
                messagebox.showinfo("Success", "File retrieved successfully!")
                self.status.config(text="File accessed successfully")
        
        except ValueError as e:
            # Handle file not found or already deleted
            messagebox.showerror("Error", str(e))
        
        except Exception as e:
            # Handle unexpected errors
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
            logging.error(f"Unexpected error during file access: {str(e)}")

    def on_closing(self):
        try:
            self.vault.close()
        except Exception as e:
            logging.error(f"Error during closing: {str(e)}")
        finally:
            self.destroy()

if __name__ == "__main__":
    root = ModernGUI()
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('Accent.TButton', font=('Arial', 12, 'bold'), foreground='white', background='#2c3e50')
    root.protocol("WM_DELETE_WINDOW", root.on_closing)
    root.mainloop()