import os
import google.generativeai as genai
import customtkinter as ctk
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from sympy import symbols, Eq, solve
from PIL import Image
from dotenv import load_dotenv
from tkinter.filedialog import askopenfilename


load_dotenv()
GENAI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GENAI_API_KEY:
    raise ValueError(
        "API key not found. Set GEMINI_API_KEY as an environment variable.")


genai.configure(api_key=GENAI_API_KEY)


analyzer = SentimentIntensityAnalyzer()


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class ChatBotApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AI ChatBot")
        self.geometry("630x430")

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=0)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)

        self.chat_display = ctk.CTkTextbox(self, wrap="word")
        self.chat_display.grid(row=0, column=0, padx=10,
                               pady=10, columnspan=2, sticky="nsew")
        self.chat_display.insert(
            "end", "ChatBot: Hello! How can I assist you?\n")
        self.chat_display.configure(state="disabled")

        self.user_input = ctk.CTkEntry(self)
        self.user_input.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.user_input.bind("<Return>", lambda event: self.process_input())

        self.send_button = ctk.CTkButton(
            self, text="Send", command=self.process_input)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

        self.image_button = ctk.CTkButton(
            self, text="Upload Image", command=self.upload_image)
        self.image_button.grid(row=2, column=0, columnspan=2, pady=10)

    def process_input(self):
        user_text = self.user_input.get().strip()
        if not user_text:
            return

        self.display_message("You", user_text)
        response = self.generate_response(user_text)
        self.display_message("ChatBot", response)
        self.user_input.delete(0, "end")

    def display_message(self, sender, message):
        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", f"{sender}: {message}\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

    def generate_response(self, text):
        if "sentiment" in text.lower():
            return f"Sentiment Score: {self.analyze_sentiment(text)}"
        if "solve" in text.lower():
            return self.solve_equation(text)
        return self.query_gemini(text)

    def analyze_sentiment(self, text):
        score = analyzer.polarity_scores(text)["compound"]
        return "Positive 😊" if score > 0.05 else "Negative 😞" if score < -0.05 else "Neutral 😐"

    def solve_equation(self, text):
        try:
            eq_str = text.replace("solve", "").strip()
            x = symbols("x")
            equation = Eq(eval(eq_str), 0)
            solution = solve(equation, x)
            return f"Solution: {solution}"
        except Exception as e:
            return f"Error solving equation: {e}"

    def query_gemini(self, user_input):
        model = genai.GenerativeModel("gemini-1.5-pro")

        context = """
        
        My Understanding of the BioCrypt Project

        Core Concept: BioCrypt is a biometric-integrated file encryption and decryption system. It uses a fingerprint sensor (connected to an Arduino) to generate a unique hash, which is then used as the basis for an encryption key. This eliminates the need for traditional passwords, enhancing security.

        Key Features:

        Fingerprint Authentication: The core security mechanism.

        AES-256 Encryption: A strong, industry-standard encryption algorithm.

        Local Storage ("The Vault"): Encrypted storage on the user's device. Files are encrypted twice for extra security. Requires email and OTP for access.

        Cloud Storage ("The Cloud"): Integration with Google Drive. Files are encrypted before upload, and access requires email and OTP.

        Safe Mail: Secure file transfer via email. Files are encrypted before sending, and a special code (referencing the encryption function) is sent with the email for decryption. Protects against Man-in-the-Middle attacks.

        Help Bot: An integrated chatbot for user assistance.

        AI-Powered File Summarization: Provides a summary of encrypted files without decrypting them, a significant usability and security feature.

        File Compression: Optional feature with Low, Medium, and High compression levels (using lossless compression).

        TimeGuard: A time-locked storage option (for both local and cloud) that automatically deletes files after a set time or failed access attempts, with cryptographic hashing for integrity checks.

        SecureFileBeam: Bluetooth-based file transfer, encrypting files before sending them between devices.

        Logging: All operations (encryption, decryption, fingerprint scans) are logged.

        User Interface: Designed for ease of use, with a high-contrast theme option.

        Technical Stack:

        Python: Main application logic, GUI (using Tkinter), file encryption, and integration with the fingerprint sensor.

        Arduino C++: Code for the Arduino to interface with the fingerprint sensor.

        PyCryptodome: For AES encryption/decryption.

        Google Generative AI: For the file summarization feature.

        pySerial: For communication between the software and the Arduino.

        Google Drive API: For cloud storage integration.

        smtplib: For email sending (OTP and Safe Mail).

        Hardware: Fingerprint sensor and Arduino board.

        Security Protocols:

        AES-256 Encryption: For all file encryption/decryption.

        Fingerprint Hashing (e.g., SHA-256): To securely store fingerprint data.

        OTP Authentication: For accessing files in local and cloud storage.

        End-to-End Encryption (Safe Mail): Protects files during email transmission.

        Team Roles: Clearly defined roles for project management, file management, accessibility features, data delivery, and supervision.

        Deliverables: A working software application (BioCrypt), comprehensive technical documentation, and a user manual.

        Timeline: Spans from December 2024 to May 2025, with key milestones.

        Budget: Very low, only covering the cost of the Arduino and fingerprint sensor.

        Risks and Mitigations: Identifies key risks (data breaches, MITM attacks, spoofing, etc.) and proposes appropriate mitigation strategies.

        Now, ask me anything! Here are some examples of the types of questions I can help with:

        Clarification: "Can you explain the difference between 'The Vault' and 'The Cloud' in more detail?"

        Technical Details: "How does the fingerprint hash get securely transmitted from the Arduino to the main program?"

        Security Concerns: "What are the potential vulnerabilities of using Google Drive for cloud storage, and how are they addressed?"

        Feature Suggestions: "Could we add a feature to allow users to share encrypted files directly with other BioCrypt users?"

        Implementation Questions: "What Python libraries would be best suited for implementing the file compression feature?"

        Risk Assessment: "What is the likelihood of a successful fingerprint spoofing attack, and how effective is the proposed mitigation?"

        Code-Related (Hypothetical): "If I wanted to implement the OTP functionality, what would the basic Python code look like?"

        Comparison: "How does BioCrypt compare to other existing file encryption solutions?"

        Project management questions How could we best proceed with the testing face of the program?

        User questions Could we add a help text to make it even more accessible?
        
        General Information
        1. What is BioCrypt? BioCrypt is a file encryption and decryption system that uses biometric authentication, such as fingerprint scans, to protect your sensitive files with advanced encryption algorithms.
        2. How does BioCrypt work? BioCrypt works by scanning your fingerprint, creating an encryption key unique to your biometric data, and using this key to encrypt or decrypt files securely.
        3. What makes BioCrypt different from other file encryption tools? BioCrypt integrates biometric authentication for a higher level of security, ensuring that only authorized users can access and decrypt files, unlike traditional password-based encryption.
        4. Is BioCrypt easy to use for non-technical users? Yes, BioCrypt is designed with simplicity in mind, featuring an intuitive interface that guides users through the encryption and decryption process with minimal technical knowledge required.
        5. Can BioCrypt be used by organizations as well as individuals? Yes, BioCrypt is suitable for both individual users and organizations looking to secure sensitive files with biometric authentication.
        6. Does BioCrypt store any personal information? No, BioCrypt does not store personal information beyond the necessary biometric data used for authentication, ensuring privacy.
        7. Is BioCrypt available for both Windows and Mac? Yes, BioCrypt is compatible with both Windows and Mac operating systems.
        8. Can BioCrypt be used on mobile devices? BioCrypt is currently not available for mobile devices, but plans for a mobile version may be considered in the future.
        9. How do I download and install BioCrypt? You can download BioCrypt from the official website and follow the installation instructions for your platform (Windows or Mac).
        10. Does BioCrypt support multi-language options? BioCrypt currently supports English but may offer other languages in future updates.
        11. Is there a version of BioCrypt for corporate use? Yes, BioCrypt offers enterprise solutions for secure file management and encryption within organizational environments.
        12. What happens if I lose access to my fingerprint sensor? If you lose access to your fingerprint sensor, you can still access encrypted files by using alternative authentication methods, such as a backup PIN or password.
        13. How does BioCrypt ensure data security? BioCrypt uses advanced encryption algorithms, along with biometric authentication, to protect files from unauthorized access, ensuring maximum data security.
        14. What encryption algorithm does BioCrypt use? BioCrypt uses AES-256 (Advanced Encryption Standard) for secure file encryption.
        15. Can BioCrypt be used to encrypt any type of file? Yes, BioCrypt can encrypt most types of files, including documents, images, videos, and archives.
        16. What type of files can I encrypt using BioCrypt? You can encrypt all file types such as text files, PDFs, photos, videos, and more.
        17. Does BioCrypt offer cloud storage? No, BioCrypt does not provide cloud storage. However, you can encrypt files stored on cloud services like Google Drive.
        18. Can I store encrypted files on Google Drive using BioCrypt? Yes, BioCrypt allows you to encrypt files and store them on Google Drive securely.
        19. Can I store encrypted files locally? Yes, you can store encrypted files locally on your computer or external drives.
        20. What is Safe Mail and how does it work? Safe Mail is a feature in BioCrypt that allows you to send encrypted emails securely. It encrypts attachments and ensures that only the intended recipient can decrypt the files.
        21. How does the TimeGuard feature work? TimeGuard protects encrypted files by setting a time limit for file access. After the limit expires, the file is automatically locked or deleted.
        22. What is SecureFileBeam? SecureFileBeam is a feature in BioCrypt that allows you to transfer encrypted files securely over networks without exposing the content to potential interception.
        23. What happens if my encrypted file is deleted by TimeGuard? If a file is deleted by TimeGuard, it cannot be recovered unless you have a backup.
        24. How does BioCrypt prevent man-in-the-middle attacks? BioCrypt uses end-to-end encryption and secure channels to prevent interception or tampering of files during transfer.
        25. How does the fingerprint-based encryption work? The fingerprint scan generates a unique encryption key based on your biometric data, ensuring that only your fingerprint can decrypt the file.
        26. Is my fingerprint data stored anywhere on the system? No, your fingerprint data is stored locally on your device and is never uploaded to external servers.
        27. How does the fingerprint sensor interact with the software? The fingerprint sensor scans your fingerprint, and the software uses it to generate an encryption key for secure file access.
        28. Can I use BioCrypt without a fingerprint sensor? Yes, BioCrypt also allows you to use alternative authentication methods, such as a PIN or password.
        29. What happens if the fingerprint scan is unsuccessful? If the scan is unsuccessful, you can try again or use alternative authentication methods.
        30. How do I register my fingerprint in BioCrypt? During the setup process, BioCrypt will prompt you to register your fingerprint by scanning it multiple times for accuracy.
        31. Can I register multiple fingerprints in BioCrypt? Yes, BioCrypt allows you to register multiple fingerprints for additional convenience.
        32. Can BioCrypt encrypt files before sending them via email? Yes, you can encrypt files with BioCrypt before attaching them to an email for secure transmission.
        33. Does BioCrypt allow me to share encrypted files securely via email? Yes, BioCrypt supports sharing encrypted files securely via email with the use of a decryption key or fingerprint authentication.
        34. How do I generate the encryption key using my fingerprint? BioCrypt generates the encryption key based on the data collected from your fingerprint scan, ensuring it's unique to you.
        35. How do I decrypt a file that I have received from someone else? To decrypt a file, use your fingerprint scan or PIN to unlock the file, provided you have the necessary decryption key.
        36. Is it possible to use BioCrypt for file compression before encryption? BioCrypt doesn't include a built-in file compression feature, but you can compress files before encrypting them with other tools.
        37. How do I change my fingerprint in BioCrypt? You can update your fingerprint by accessing the settings within BioCrypt and following the registration process again.
        38. Can I encrypt a file and share it securely via Bluetooth? Yes, BioCrypt supports encrypted file sharing over Bluetooth, ensuring the file remains secure during transfer.
        39. Does BioCrypt use OTP (One-Time Password) for added security? BioCrypt may offer OTP as an additional layer of security for certain actions, such as access to encrypted files.
        40. How is OTP generated and delivered to the user? OTP is typically generated via an authentication app or sent through email and must be entered to complete a transaction or file decryption.
        41. Can I access my files if I lose my phone or computer? Yes, you can access your encrypted files from another device, provided you have your backup PIN or OTP available.
        42. Does BioCrypt provide file access logs? Yes, BioCrypt can track file access and provide detailed logs for audit purposes.
        43. Can I track every operation performed in BioCrypt? Yes, BioCrypt provides an operation history that lets you track file encryption, decryption, and other actions performed.
        44. What is the Help Bot and how can it assist me? The Help Bot is an in-app support tool designed to provide assistance with frequently asked questions, troubleshooting, and guiding you through the BioCrypt system.
        45. How does BioCrypt improve data protection compared to traditional encryption methods? BioCrypt uses biometric authentication combined with AES-256 encryption, offering a higher level of security than traditional password-based systems.
        46. What are the key features of BioCrypt for protecting sensitive data? Key features include biometric-based encryption, secure cloud storage options, TimeGuard, and Safe Mail for encrypted email communication.
        47. How do I check if my file is properly encrypted? After encryption, BioCrypt ensures that the file format changes (e.g., the file will appear as an encrypted .bio file). You can try to open the file to verify that it requires authentication.
        48. Can I encrypt multiple files at once with BioCrypt? Yes, BioCrypt allows bulk encryption of multiple files in a single operation.
        49. Can I use BioCrypt to encrypt videos or images? Yes, BioCrypt can encrypt any type of file, including videos, images, and documents.
        50. Can BioCrypt be used for file decryption after a successful scan? Yes, once the fingerprint scan or PIN is validated, you can decrypt the file immediately.

        Name of the leader of the BioCrypt project is abdullah badawy.
        
        """

        response = model.generate_content(
            f"{context}\nUser Question: {user_input}")

        return response.text if response else "I'm sorry, I couldn't process that request."

    def upload_image(self):
        file_path = askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
        if not file_path:
            self.display_message("ChatBot", "No image selected.")
            return

        try:
            img = Image.open(file_path)
            img.show()
            self.display_message(
                "ChatBot", "Image uploaded and displayed successfully.")
            description = self.analyze_image(file_path)
            self.display_message("ChatBot", f"Image Analysis: {description}")
        except Exception as e:
            self.display_message("ChatBot", f"Error opening image: {e}")

    def analyze_image(self, file_path):
        model = genai.GenerativeModel("gemini-1.5-flash")

        try:
            with open(file_path, "rb") as img_file:
                img_bytes = img_file.read()

            response = model.generate_content(
                [
                    {"role": "user", "parts": [
                        {"text": "This is a picture of the BioCrypt program. Explain if there is a problem or describe what I did not see."},
                        {"mime_type": "image/jpeg", "data": img_bytes}
                    ]}
                ]
            )

            return response.text if response else "Unable to analyze the image."

        except Exception as e:
            return f"Error analyzing image: {e}"


if __name__ == "__main__":
    app = ChatBotApp()
    app.mainloop()
