from pathlib import Path


from tkinter import Tk, Canvas, Entry, Text, Button, PhotoImage


OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"F:\projects\BioCrypt\Part-2\assets\frame0")


def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)

def truncate_text(text, max_length):
    return text[0:max_length] + "..." 

window = Tk()

window.geometry("553x306")
window.configure(bg = "#FFFFFF")


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
image_image_1 = PhotoImage(
    file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(
    448.0,
    99.0,
    image=image_image_1
)

canvas.create_text(
    40.0,
    19.0,
    anchor="nw",
    text="Name",
    fill="#000000",
    font=("Roboto CondensedExtraBoldItalic", 44 * -1))


canvas.create_text(
    28,
    90.0,
    anchor="nw",
    text= " Image",
    fill="#000000",
    font=("Roboto CondensedExtraBoldItalic", 44 * -1))


canvas.create_text(
    280,  
    250.0,  
    anchor="center", 
    text=truncate_text("Young man with curly hair, smiling against a blue background.",1),
    fill="#000000",
    font=("Roboto Condensed ExtraBold Italic", 24 * -1),
    width=500
    ,
)
window.resizable(True, True)
window.mainloop()
