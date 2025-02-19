import os
import re
import google.generativeai as genai
import customtkinter as ctk
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from sympy import symbols, Eq, solve
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
GENAI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GENAI_API_KEY:
    raise ValueError("API key not found. Set GEMINI_API_KEY as an environment variable.")

genai.configure(api_key=GENAI_API_KEY)

# Initialize sentiment analyzer
analyzer = SentimentIntensityAnalyzer()

# GUI setup
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ChatBotApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AI ChatBot")
        self.geometry("630x430")

        # Configure grid to allow resizing
        self.grid_rowconfigure(0, weight=1)  # Make chat_display expandable
        self.grid_rowconfigure(1, weight=0)  # Keep input field static
        self.grid_rowconfigure(2, weight=0)  # Keep buttons static
        self.grid_columnconfigure(0, weight=1)  # Expand input field horizontally
        self.grid_columnconfigure(1, weight=0)  # Keep send button static

        # Chat display
        self.chat_display = ctk.CTkTextbox(self, wrap="word")
        self.chat_display.grid(row=0, column=0, padx=10, pady=10, columnspan=2, sticky="nsew")
        self.chat_display.insert("end", "ChatBot: Hello! How can I assist you?\n")
        self.chat_display.configure(state="disabled")

        # User input
        self.user_input = ctk.CTkEntry(self)
        self.user_input.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.user_input.bind("<Return>", lambda event: self.process_input())

        # Send button
        self.send_button = ctk.CTkButton(self, text="Send", command=self.process_input)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

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
        self.chat_display.see("end")  # Auto-scroll to the latest message

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
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content(user_input)
        return response.text

if __name__ == "__main__":
    app = ChatBotApp()
    app.mainloop()