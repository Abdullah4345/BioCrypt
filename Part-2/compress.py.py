import os
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

def is_compressed(file_path):
    compressed_extensions = ['.zip', '.rar', '.gz', '.tar', '.7z']
    return any(file_path.lower().endswith(ext) for ext in compressed_extensions)

def compress_file(file_path, output_path, compression_level):
    try:
        compression_mapping = {1: zipfile.ZIP_STORED, 5: zipfile.ZIP_DEFLATED, 9: zipfile.ZIP_BZIP2}
        compression_type = compression_mapping.get(compression_level, zipfile.ZIP_DEFLATED)
        
        with zipfile.ZipFile(output_path, 'w', compression=compression_type) as zipf:
            if os.path.isdir(file_path):  
                for root, _, files in os.walk(file_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        arcname = os.path.relpath(full_path, start=os.path.dirname(file_path))
                        zipf.write(full_path, arcname)
            else:
                zipf.write(file_path, os.path.basename(file_path))
        return output_path
    except Exception as e:
        messagebox.showerror("Compression Error", f"An error occurred during compression: {e}")
        return None

def decompress_file(file_path, output_folder):
    try:
        with zipfile.ZipFile(file_path, 'r') as zipf:
            zipf.extractall(output_folder)
        return output_folder
    except Exception as e:
        messagebox.showerror("Decompression Error", f"An error occurred during decompression: {e}")
        return None

def process_file(compress=True):
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")]) if not compress_folder_var.get() else filedialog.askdirectory()
    if not file_path:
        return
    
    if compress and is_compressed(file_path):
        messagebox.showinfo("Info", "The selected file is already compressed. Skipping compression.")
        return
    
    compression_level = compression_level_var.get()
    try:
        progress_label.config(text="Compressing..." if compress else "Decompressing...")
        progress_bar.start()
        root.update()
        
        if compress:
            default_output_name = os.path.basename(file_path) + ".zip"
            output_path = filedialog.asksaveasfilename(defaultextension=".zip", initialfile=default_output_name, filetypes=[("ZIP Files", "*.zip")])
            if output_path:
                result = compress_file(file_path, output_path, compression_level)
                if result:
                    messagebox.showinfo("Success", f"File compressed successfully:\n{output_path}")
                    open_location_button.config(state=tk.NORMAL, command=lambda: os.startfile(os.path.dirname(output_path)))
        else:
            output_folder = filedialog.askdirectory(title="Select Output Folder for Decompression")
            if output_folder:
                result = decompress_file(file_path, output_folder)
                if result:
                    messagebox.showinfo("Success", f"Files decompressed successfully to:\n{output_folder}")
                    open_location_button.config(state=tk.NORMAL, command=lambda: os.startfile(output_folder))
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
    finally:
        progress_bar.stop()
        progress_label.config(text="")

def create_gui():
    global root, compression_level_var, progress_label, progress_bar, open_location_button, compress_folder_var

    root = tk.Tk()
    root.title("File Compression Tool")
    root.geometry("500x500")
    root.resizable(False, False)
    
    style = ttk.Style()
    style.theme_use("clam")
    
    main_frame = tk.Frame(root, bg="#0F1A17")
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    title_label = tk.Label(main_frame, text="File Compression & Decompression Tool", font=("Arial", 13, "bold"), bg="#0F1A17", fg="#00FF00")
    title_label.pack(pady=10)

    instruction_label = tk.Label(main_frame, text="Select a file or folder and choose a compression level:", bg="#0F1A17", fg="#00FF00")
    instruction_label.pack(pady=5)

    compression_level_var = tk.IntVar(value=5)
    options_frame = ttk.Frame(main_frame)
    options_frame.pack(pady=5)

    ttk.Label(options_frame, text="Compression Level:").grid(row=0, column=0, padx=5, sticky="w")
    ttk.Radiobutton(options_frame, text="Low", variable=compression_level_var, value=1).grid(row=0, column=1, padx=5)
    ttk.Radiobutton(options_frame, text="Medium", variable=compression_level_var, value=5).grid(row=0, column=2, padx=5)
    ttk.Radiobutton(options_frame, text="High", variable=compression_level_var, value=9).grid(row=0, column=3, padx=5)

    compress_folder_var = tk.BooleanVar(value=False)
    compress_folder_checkbox = tk.Checkbutton(main_frame, text="Compress Entire Folder", variable=compress_folder_var, bg="#0F1A17", fg="#00FF00")
    compress_folder_checkbox.pack(pady=5)

    ttk.Button(main_frame, text="Compress File/Folder", command=lambda: process_file(compress=True)).pack(pady=5)
    ttk.Button(main_frame, text="Decompress File/Folder", command=lambda: process_file(compress=False)).pack(pady=5)

    progress_label = tk.Label(main_frame, text="", bg="#0F1A17", fg="#00FF00")
    progress_label.pack(pady=5)
    progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="indeterminate")
    progress_bar.pack(pady=5)

    open_location_button = ttk.Button(main_frame, text="Open Output Location", state=tk.DISABLED)
    open_location_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()