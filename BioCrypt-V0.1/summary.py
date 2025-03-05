import json
import random
from PIL import Image, ImageTk
from google import genai
from google.genai import types
from tkinter import filedialog ,Tk,Toplevel, Canvas, Entry, Text, Button, PhotoImage, Frame, font, Listbox, Scrollbar, Label, END
import time
import os
from pathlib import Path
import base64
from cryptography.fernet import Fernet

JSON_FILE = "BioCrypt-V0.1/data/summary.json"

def generate_key():
    
    return "Ju-Nu7yW9U1CwF2A7Mq5KnJtWfCfPEm7eZdryB6r_Xs="
        
def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data).decode()

def load_json():
    
    if not os.path.exists(JSON_FILE):
        data = json.dumps({})
        encrypted_data = encrypt_data(data, key)
        with open(JSON_FILE, "wb") as file:
            file.write(encrypted_data)
        return {}
    
    with open(JSON_FILE, "rb") as file:
        encrypted_data = file.read()
    
    try:
        decrypted_data = decrypt_data(encrypted_data, key)
        return json.loads(decrypted_data)
    except Exception as e:
        print("Error decrypting the file:", e)
        return {}

def save_json(data):
    encrypted_data = encrypt_data(json.dumps(data, indent=4), key)
    with open(JSON_FILE, "wb") as file:
        file.write(encrypted_data)

key = generate_key()

data = load_json()

def write_json(response, file_name, file_type):
    data[file_name] = {"File_type": file_type, "desc": response}
    
    save_json(data)
    print("Response written to summary.json")



def select_file():
    
# Create the root window
    root = Tk()
    root.withdraw()  # Hide the main window
    file_types = [
        ("Audio Files", "*.wav;*.mp3;*.aiff;*.aac;*.ogg;*.flac"),
        ("Image Files", "*.png;*.jpeg;*.jpg;*.webp;*.heic;*.heif"),
        ("Video Files", "*.mp4;*.mpeg;*.mov;*.avi;*.x-flv;*.mpg;*.webm;*.wmv;*.3gpp"),
        ("Documents", "*.pdf"),
        ("Scripts", "*.js;*.py;*.json"),
        ("Text Files", "*.txt;*.html;*.css;*.md;*.csv;*.xml;*.rtf"),
    ]
    
    file_path = filedialog.askopenfilename(title="Select a file", filetypes=file_types)
    if file_path:
        print(f"Selected file: {file_path}")
    return file_path
def response_img(file_path):
    
    
    image = Image.open(file_path)
    
    client = genai.Client(api_key="Api")
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=["summarize it to 10 words only without any another response and be precise in names and info", image]
    )
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Img")
def response_audio(file_path):
    client = genai.Client(api_key="Api")

    audio_file = client.files.upload(file=file_path)

    response = client.models.generate_content(
    model='gemini-2.0-flash',
    contents=[
        'summarize it to 10 words only without any another response and be precise in names and info',
        audio_file,
    ]
)
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Audio")
def response_video(file_path):
    client = genai.Client(api_key="Api")

    print("Uploading file...")
    video_file = client.files.upload(file=file_path)
    print(f"Completed upload: {video_file.uri}")
    
    while video_file.state.name == "PROCESSING":
        time.sleep(1)
        video_file = client.files.get(name=video_file.name)

    if video_file.state.name == "FAILED":
        raise ValueError(video_file.state.name)

    response = client.models.generate_content(
    model='gemini-2.0-flash',
    contents=[
        video_file,
        "summarize it to 10 words only without any another response and be precise in names and info"])
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Video")
def response_file(file_path):
    client = genai.Client(api_key="Api")
    file = client.files.upload(file =file_path)
    response = client.models.generate_content(
        model='gemini-2.0-flash',
        contents=[
            file,
            "summarize it to 10 words only without any another response and be precise in names and info"])
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Document")
def Data_Frame(name,type,desc):

    def truncate_text(text, max_length):
        return text[0:max_length] + "..." if len(text)>max_length else text

    def get_frame_size(desc):
        return  (len(desc)/90)*70 if len(desc)>90 else 1;
    
    OUTPUT_PATH = Path(__file__).parent
    ASSETS_PATH = OUTPUT_PATH / "assets" / "frame0"
    def relative_to_assets(path: str) -> Path:
        return ASSETS_PATH / Path(path)
    
    # Load and place the background image
    window = Toplevel()
    window.geometry(f"553x{str(int(306+get_frame_size(desc)))}")
    window.configure(bg="#FFFFFF")
    bg_image = Image.open(relative_to_assets("background.jpg"))  # Change to your actual background image
    bg_image = bg_image.resize((553, int(306+get_frame_size(desc))), Image.LANCZOS)  # Resize to fit the window
    bg_photo = ImageTk.PhotoImage(bg_image)

    window.bg_photo = bg_photo
    


    # Load font from project folder
    custom_font40 = font.Font(family="Roboto Condensed", size=28, weight="bold", slant="italic")
    custom_font44 = font.Font(family="Roboto Condensed", size=32, weight="bold", slant="italic")
    custom_font28 = font.Font(family="Roboto Condensed", size=20, weight="bold", slant="italic")

    canvas = Canvas(
        window,
        bg="#FFFFFF",
        height=int(306+get_frame_size(desc)),
        width=553,
        bd=0,
        highlightthickness=0,
        relief="ridge"
    )

    canvas.place(x=0, y=0)
    
        # Set image as background
    canvas.create_image(0, 0, anchor="nw", image=window.bg_photo)


    image_image_1 = PhotoImage(file=relative_to_assets("image_1.png"))
    canvas.create_image(474.0, 125.0, image=image_image_1)

    canvas.create_text(
        10.0,
        20.0,
        anchor="nw",
        text=truncate_text(name, 15),
        fill="#000000",
        font=custom_font44
    )

    canvas.create_text(
        10.0,
        118.0,
        anchor="nw",
        text="Type:" + type,
        fill="#000000",
        font=custom_font40
    )

    canvas.create_text(
        10.0,
        215.0,
        anchor="nw",
        text=desc,
        fill="#000000",
        font=custom_font28,
        width=540, 
        justify="center",
        
    )

    window.resizable(False, False)
    window.mainloop()

def on_file_select(event):
    # Get the selected file name
    selected_index = event.widget.curselection()
    if selected_index:
        file_name = event.widget.get(selected_index)
        # Access the data associated with the selected file
        file_data = data.get(file_name, {})
        # Perform your specific command here
        Data_Frame(file_name,file_data["File_type"],file_data["desc"])
def create_window():
    # Load data from JSON
    data = load_json()

    # Create the main window
    root = Tk()
    root.title("Saved Files")
    root.geometry("400x300")

    # Create a label
    label = Label(root, text="Saved Files:")
    label.pack()

    # Create a scrollbar
    scrollbar = Scrollbar(root)
    scrollbar.pack(side="right", fill="y")

    # Create a listbox
    listbox = Listbox(root, yscrollcommand=scrollbar.set)
    listbox.pack(fill="both", expand=True)
# Populate the listbox with file names
    for file_name in data.keys():
        listbox.insert(END, file_name)

    listbox.bind('<<ListboxSelect>>', on_file_select)

    # Configure the scrollbar
    scrollbar.config(command=listbox.yview)

    # Start the Tkinter event loop
    root.mainloop()

if __name__ == "__main__":
    create_window()