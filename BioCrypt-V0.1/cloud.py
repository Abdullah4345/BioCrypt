import os
import random
import smtplib
import string
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle
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


SCOPES = ['https://www.googleapis.com/auth/drive.file']


class GoogleDriveUploader:
    def __init__(self):
        self.creds = None
        self.email_file_mapping = {}  
        self.authenticate()
        self.load_mapping()  

    def load_mapping(self):
        """Load the file-to-email mapping from the CSV file."""
        try:
            with open('data/file_mapping.csv', mode='r') as file:
                reader = csv.reader(file)
                self.email_file_mapping = {row[0]: row[1] for row in reader}
        except FileNotFoundError:
            pass 

    def authenticate(self):
        """Authenticate the user with Google Drive API and request a new token if needed."""
        if os.path.exists('data/token.pickle'):
            with open('data/token.pickle', 'rb') as token:
                self.creds = pickle.load(token)

        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'client_secret_800944173395-66ueils05h7sf7ois00jvlv0g3276o82.apps.googleusercontent.com.json', SCOPES)
                self.creds = flow.run_local_server(port=0)

            with open('data/token.pickle', 'wb') as token:
                pickle.dump(self.creds, token)

    def list_files(self):
        """List files uploaded to Google Drive."""
        try:
            service = build('drive', 'v3', credentials=self.creds)
            results = service.files().list(pageSize=100, fields="files(id, name)").execute()
            return results.get('files', [])
        except Exception as e:
            return str(e)

    def upload_file(self, file_path, user_email):
        """Upload a file to Google Drive and associate with the user's email."""
        try:
            service = build('drive', 'v3', credentials=self.creds)
            file_metadata = {'name': os.path.basename(file_path)}
            media = MediaFileUpload(
                file_path, mimetype='application/octet-stream')
            file = service.files().create(body=file_metadata,
                                          media_body=media, fields='id').execute()

            file_id = file.get('id')
            self.email_file_mapping[file_id] = user_email  

            
            with open('data/file_mapping.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([file_id, user_email])

            return file_id
        except Exception as e:
            return str(e)

    def download_file(self, file_id, save_path, user_email):
        """Download a file from Google Drive if the email matches."""
        try:
            
            if self.email_file_mapping.get(file_id) != user_email:
                return False, "Email does not match the file owner."

            service = build('drive', 'v3', credentials=self.creds)
            request = service.files().get_media(fileId=file_id)
            with open(save_path, 'wb') as file:
                downloader = MediaIoBaseDownload(file, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
            return True, "File downloaded successfully."
        except Exception as e:
            return False, str(e)

    def delete_file(self, file_id):
        """Delete a file from Google Drive."""
        try:
            service = build('drive', 'v3', credentials=self.creds)
            service.files().delete(fileId=file_id).execute()
            return True, "File deleted successfully."
        except Exception as e:
            return False, str(e)


class OTPManager:
    def __init__(self):
        self.otp = None

    def generate_otp(self):
        """Generate a random 6-digit OTP."""
        self.otp = ''.join(random.choices(string.digits, k=6))
        return self.otp

    def send_otp(self, user_email):
        """Send OTP to the provided email."""
        try:
            otp = self.generate_otp()
            message = MIMEText(f"Your OTP is: {otp}")
            message['Subject'] = 'Your OTP for Verification'
            message['From'] = 'your_email@gmail.com'
            message['To'] = user_email

            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login('biocryptprogram@gmail.com',
                             'nwxv ztza szsi trcx')
                server.sendmail('your_email@gmail.com',
                                user_email, message.as_string())

            return otp
        except Exception as e:
            return str(e)


class FileManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Google Cloud")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        self.root.config(bg=var1["bg"])
        self.uploader = GoogleDriveUploader()
        self.otp_manager = OTPManager()

        
        self.title_label = tk.Label(
            root, text="Google Cloud", bg=var1["bg"], fg=var2["fg"], font=("Courier", 55, "bold"))
        self.title_label.pack(pady=2)

        style = ttk.Style()
        style.configure(
            "Treeview", background=var2["fg"], fieldbackground=var2["fg"], foreground=var1["bg"])

        
        self.tree = ttk.Treeview(root, columns=(
            "ID", "Name"), show="headings", height=15,)
        self.tree.heading("ID", text="File ID")
        self.tree.heading("Name", text="File Name")
        self.tree.column("ID", width=300)
        self.tree.column("Name", width=300)
        self.tree.pack(pady=5)

        
        self.buttons_frame = tk.Frame(root, bg=var1["bg"])
        self.upload_button = tk.Button(self.buttons_frame, text="     Upload File      ", command=self.upload_file,
                                       bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12))
        self.download_button = tk.Button(self.buttons_frame, text="Download Selected File", command=self.download_file,
                                         bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12))
        self.delete_button = tk.Button(self.buttons_frame, text=" Delete Selected File ", command=self.delete_file,
                                       bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12))
        self.refresh_button = tk.Button(self.buttons_frame, text="       Refresh        ", command=self.refresh_file_list,
                                        bg=var1["bg"], fg=var2["fg"], relief="flat", bd=0, highlightthickness=0, font=("Courier", 12))

        
        self.upload_button.pack(pady=3)
        self.download_button.pack(pady=3)
        self.delete_button.pack(pady=3)
        self.refresh_button.pack(pady=3)

        self.buttons_frame.pack(pady=1)

        
        self.list_files()

    def upload_file(self):
        """Upload a file to Google Drive after email verification."""
        email = self.ask_email()
        if not email:
            return

        otp = self.otp_manager.send_otp(email)
        entered_otp = self.ask_otp()

        if entered_otp == otp:
            file_path = filedialog.askopenfilename()
            if file_path:
                file_id = self.uploader.upload_file(file_path, email)
                if file_id:
                    messagebox.showinfo(
                        "Success", f"File uploaded successfully! File ID: {file_id}")
                else:
                    messagebox.showerror("Error", "Failed to upload the file.")
        else:
            messagebox.showerror("Error", "Incorrect OTP. Upload failed.")

    def ask_email(self):
        """Prompt the user for their email."""
        email = simpledialog.askstring("Email", "Please enter your email:")
        return email

    def ask_otp(self):
        """Prompt the user for the OTP."""
        otp = simpledialog.askstring(
            "OTP", "Please enter the OTP sent to your email:")
        return otp

    def list_files(self):
        """List files and display them in the treeview."""
        files = self.uploader.list_files()
        if isinstance(files, list):
            self.tree.delete(*self.tree.get_children())
            for file in files:
                self.tree.insert("", "end", values=(file['id'], file['name']))
        else:
            messagebox.showerror("Error", f"Failed to list files: {files}")

    def refresh_file_list(self):
        """Refresh the file list in the treeview."""
        self.list_files()

    def download_file(self):
        """Download the selected file after email verification."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected!")
            return

        file_id, file_name = self.tree.item(selected_item, "values")
        email = self.uploader.email_file_mapping.get(file_id)
        if not email:
            messagebox.showerror(
                "Error", "No associated email found for this file.")
            return

        otp = self.otp_manager.send_otp(email)
        entered_otp = self.ask_otp()

        if entered_otp == otp:
            save_path = filedialog.asksaveasfilename(initialfile=file_name)
            if save_path:
                success, message = self.uploader.download_file(
                    file_id, save_path, email)
                if success:
                    messagebox.showinfo("Success", message)
                else:
                    messagebox.showerror("Error", message)
        else:
            messagebox.showerror("Error", "Incorrect OTP. Download failed.")

    def delete_file(self):
        """Delete the selected file after OTP verification."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected!")
            return

        file_id, file_name = self.tree.item(selected_item, "values")
        email = self.uploader.email_file_mapping.get(file_id)
        if not email:
            messagebox.showerror(
                "Error", "No associated email found for this file.")
            return

        otp = self.otp_manager.send_otp(email)
        entered_otp = self.ask_otp()

        if entered_otp == otp:
            success, message = self.uploader.delete_file(file_id)
            if success:
                messagebox.showinfo("Success", message)
                self.list_files()  
            else:
                messagebox.showerror("Error", message)
        else:
            messagebox.showerror("Error", "Incorrect OTP. Delete failed.")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileManagerApp(root)
    root.mainloop()
