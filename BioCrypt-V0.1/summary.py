import json
import random
from PIL import Image, ImageTk
from google import genai
from google.genai import types
from tkinter import filedialog ,Tk, Canvas, Entry, Text, Button, PhotoImage, Frame, font
import time
import os
from pathlib import Path


try:
        with open("summary.json", "r") as file:
            data = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
            data = {}

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
    window = Tk()
    window.geometry(f"553x{str(int(306+get_frame_size(desc)))}")
    window.configure(bg="#FFFFFF")
    bg_image = Image.open(relative_to_assets("background.jpg"))  # Change to your actual background image
    bg_image = bg_image.resize((553, int(306+get_frame_size(desc))), Image.LANCZOS)  # Resize to fit the window
    bg_photo = ImageTk.PhotoImage(bg_image)

    


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
    canvas.create_image(0, 0, anchor="nw", image=bg_photo)


    image_image_1 = PhotoImage(
        file=relative_to_assets("image_1.png"))
    image_1 = canvas.create_image(
        474.0,
        125.0,
        image=image_image_1
    )

    # canvas.create_rectangle(
    #     5.0,
    #     10.0,
    #     372.0,
    #     81.0,
    #     fill="#D9D9D9",
    #     outline="")

    # canvas.create_rectangle(
    #     5.0,
    #     112.0,
    #     205.0,
    #     183.0,
    #     fill="#D9D9D9",
    #     outline="")

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
    
