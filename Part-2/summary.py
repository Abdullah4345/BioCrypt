import json
import random
from PIL import Image, ImageTk
from google import genai
from google.genai import types
from tkinter import filedialog ,Tk, Canvas, Entry, Text, Button, PhotoImage, Frame
import time
import os
from pathlib import Path





try:
        with open("summary.json", "r") as file:
            data = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
            data = {}

# def get_random():
#     random_id = random.randint(1000, 9999)
#     while str(random_id) in data:
#         random_id = random.randint(1000, 9999)
#     return str(random_id)
def write_json(response,file_name, type):
    data[file_name] = {"File_type":type, "desc":response}
    
    with open("Part-2/summary.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

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
    
    client = genai.Client(api_key="AIzaSyDLpW4BEUngeE7LajD_zWXR8ecC-QyfQd0")
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=["summarize it to 10 words only without any another response and be precise in names and info", image]
    )
    print(response.text)
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Img")
    
    
    
def response_audio(file_path):
    client = genai.Client(api_key="AIzaSyDLpW4BEUngeE7LajD_zWXR8ecC-QyfQd0")

    audio_file = client.files.upload(file=file_path)

    response = client.models.generate_content(
    model='gemini-2.0-flash',
    contents=[
        'summarize it to 10 words only without any another response and be precise in names and info',
        audio_file,
    ]
)
    print(response.text)
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Audio")

    

def response_video(file_path):
    client = genai.Client(api_key="AIzaSyDLpW4BEUngeE7LajD_zWXR8ecC-QyfQd0")

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
    print(response.text)
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Video")

    

def response_file(file_path):
    client = genai.Client(api_key="AIzaSyDLpW4BEUngeE7LajD_zWXR8ecC-QyfQd0")
    file = client.files.upload(file =file_path)
    response = client.models.generate_content(
        model='gemini-2.0-flash',
        contents=[
            file,
            "summarize it to 10 words only without any another response and be precise in names and info"])
    print(response.text)    
    write_json(response.text,os.path.splitext(file_path)[0].split("/")[-1],"Document")


def Data_Frame():

    def truncate_text(text, max_length):
        return text[0:max_length] + "..." if len(text)>max_length else text

    window = Tk()
    window.geometry("553x306")
    window.configure(bg="#FFFFFF")
   

    canvas = Canvas(
    window,
    bg = "#FFFFFF",
    height = 306,
    width = 553,
    bd = 0,
    highlightthickness = 0,
    relief = "ridge"
)

    canvas.place(x = 0, y = 0)
    
    # Load and place the background image
    bg_image = Image.open("assets/frame0/background.jpg")  # Change to your actual background image
    bg_image = bg_image.resize((553, 306), Image.LANCZOS)  # Resize to fit the window
    bg_photo = ImageTk.PhotoImage(bg_image)

    # Set image as background
    canvas.create_image(0, 0, anchor="nw", image=bg_photo)
    
    
    
    image_image_1 = PhotoImage(
        file=("assets/frame0/image_1.png"))
    image_1 = canvas.create_image(
        480.0,
        130.0,
        image=image_image_1
    )

    canvas.create_text(
        30.0,
        19.0,
        anchor="nw",
        text=truncate_text("1987465FNW123dkUMJ8",18),
        fill="#000000",
        font=("Roboto CondensedExtraBoldItalic", 30 * -1))


    canvas.create_text(
        30,
        70.0,
        anchor="nw",
        text= "Type : Image",
        fill="#000000",
        font=("Roboto CondensedExtraBoldItalic", 30 * -1))


    canvas.create_text(
        30,  # X-coordinate (adjust based on canvas width)
        171.0,  # Y-coordinate
        anchor="w",  # Center alignment
        text="Young man with curly hair, smiling against a blue background.",
        fill="#000000",
        font=("Roboto Condensed ExtraBold Italic", 30 * -1),
        width=400# Adjust the width to wrap text properly
        ,
    )
    window.resizable(False, False)
    window.mainloop()




def main():

    IMAGE_EXTENSIONS = {".png", ".jpeg", ".jpg", ".webp", ".heic", ".heif"}
    AUDIO_EXTENSIONS = {".wav", ".mp3", ".aiff", ".aac", ".ogg", ".flac"}
    VIDEO_EXTENSIONS = {".mp4", ".mpeg", ".mov", ".avi", ".x-flv", ".mpg", ".webm", ".wmv", ".3gpp"}
    DOCUMENT_EXTENSIONS = {".pdf",".js", ".py",".txt", ".html", ".css", ".md", ".csv", ".xml", ".rtf"}

    file_path = select_file()
    ext = os.path.splitext(file_path)[1].lower()  # Get file extension in lowercase
    if ext in IMAGE_EXTENSIONS:
        response_img(file_path)
    elif ext in AUDIO_EXTENSIONS:
        response_audio(file_path)
    elif ext in VIDEO_EXTENSIONS:
        response_video(file_path)
    elif ext in DOCUMENT_EXTENSIONS:
        response_file(file_path)
    else:
        print("Unknown file type.") 
    
Data_Frame()