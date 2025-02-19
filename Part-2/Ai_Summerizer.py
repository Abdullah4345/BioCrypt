import PIL.Image
import json
import random
from google import genai
from google.genai import types
import tkinter as tk
from tkinter import filedialog
import time
import os


try:
        with open("summary.json", "r") as file:
            data = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
        data = {}

def get_random():
    random_id = random.randint(1000, 9999)
    while str(random_id) in data:
        random_id = random.randint(1000, 9999)
    return str(random_id)
def write_json(response):
    data[get_random()] = response
    
    with open("summary.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

    print("Response written to summary.json")
def select_file():
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

# Create the root window
root = tk.Tk()
root.withdraw()  # Hide the main window

def response_img(file_path):
    
    
    image = PIL.Image.open(file_path)
    
    client = genai.Client(api_key="AIzaSyDLpW4BEUngeE7LajD_zWXR8ecC-QyfQd0")
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=["summarize it to 10 words only without any another response and be precise in names and info", image]
    )
    print(response.text)
    
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
    

def response_file(file_path):
    client = genai.Client(api_key="AIzaSyDLpW4BEUngeE7LajD_zWXR8ecC-QyfQd0")
    file = client.files.upload(file =file_path)
    response = client.models.generate_content(
        model='gemini-2.0-flash',
        contents=[
            file,
            "summarize it to 10 words only without any another response and be precise in names and info"])
    print(response.text)    


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
        response_audio(file_path);
    elif ext in VIDEO_EXTENSIONS:
        response_video(file_path)
    elif ext in DOCUMENT_EXTENSIONS:
        response_file(file_path);
    else:
        print("Unknown file type.") 
main()
    
