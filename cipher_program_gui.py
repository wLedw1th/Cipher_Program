# cipher_program_gui.py
# A GUI cipher program implementing Caesar, Vigenère, and Substitution ciphers using Tkinter.
# Author: Will Ledwith
# Date Created: 19th November 2025

# Library Imports
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import csv
import os
from datetime import datetime


# Logging Function - Saves cipher operations to a CSV file
def log_cipher_operation(cipher_type, original_text, operation, output_text):
    log_file = "cipher_log.txt"
    file_exists = os.path.isfile(log_file)
    
    with open(log_file, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # Write header if file is new
        if not file_exists:
            writer.writerow(["Timestamp", "Cipher Type", "Original Text", "Operation", "Output Text"])
        # Write the log entry
        timestamp = datetime.now().strftime("%d %m %Y %H:%M:%S")
        writer.writerow([timestamp, cipher_type, original_text, operation, output_text])


# Caesar Cipher Function
def caesar_cipher(text, shift, operation):
    textArray = list(text)
    shift_value = shift if operation == "encrypt" else -shift
    
    for i in range(len(textArray)):
        char = textArray[i]
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - ascii_offset + shift_value) % 26 + ascii_offset
            textArray[i] = chr(shifted)
    
    result = ''.join(textArray)
    log_operation = "Encrypted" if operation == "encrypt" else "Decrypted"
    log_cipher_operation("Caesar Cipher", text, log_operation, result)
    return result


# Vigenère Cipher Function
def vigenere_cipher(text, key, operation):
    textArray = list(text)
    keyArray = list(key)
    keyLength = len(keyArray)
    keyIndex = 0
    
    for i in range(len(textArray)):
        char = textArray[i]
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shift = ord(keyArray[keyIndex % keyLength].lower()) - ord('a')
            if operation == "decrypt":
                shift = -shift
            shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
            textArray[i] = chr(shifted)
            keyIndex += 1
    
    result = ''.join(textArray)
    log_operation = "Encrypted" if operation == "encrypt" else "Decrypted"
    log_cipher_operation("Vigenère Cipher", text, log_operation, result)
    return result


# Substitution Cipher Function
def substitution_cipher(text, key, operation):
    if len(key) != 26:
        raise ValueError(f"Key must be exactly 26 letters. You provided {len(key)} letters.")
    
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    textArray = list(text)
    
    if operation == "encrypt":
        keyMap = {alphabet[i]: key[i] for i in range(26)}
    else:
        keyMap = {key[i]: alphabet[i] for i in range(26)}
    
    for i in range(len(textArray)):
        char = textArray[i]
        if char.isalpha():
            is_upper = char.isupper()
            mapped_char = keyMap[char.upper()]
            textArray[i] = mapped_char if is_upper else mapped_char.lower()
    
    result = ''.join(textArray)
    log_operation = "Encrypted" if operation == "encrypt" else "Decrypted"
    log_cipher_operation("Substitution Cipher", text, log_operation, result)
    return result


# GUI Application Class
class CipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Program")
        self.root.geometry("700x600")
        self.root.resizable(False, False)
        
        # Create main container
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Cipher Tool", font=("Arial", 20, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Cipher Type Selection
        ttk.Label(main_frame, text="Select Cipher:", font=("Arial", 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.cipher_var = tk.StringVar(value="Caesar")
        cipher_frame = ttk.Frame(main_frame)
        cipher_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Radiobutton(cipher_frame, text="Caesar", variable=self.cipher_var, value="Caesar", command=self.update_key_field).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(cipher_frame, text="Vigenère", variable=self.cipher_var, value="Vigenere", command=self.update_key_field).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(cipher_frame, text="Substitution", variable=self.cipher_var, value="Substitution", command=self.update_key_field).pack(side=tk.LEFT, padx=5)
        
        # Operation Selection
        ttk.Label(main_frame, text="Operation:", font=("Arial", 12)).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.operation_var = tk.StringVar(value="encrypt")
        operation_frame = ttk.Frame(main_frame)
        operation_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Radiobutton(operation_frame, text="Encrypt", variable=self.operation_var, value="encrypt").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(operation_frame, text="Decrypt", variable=self.operation_var, value="decrypt").pack(side=tk.LEFT, padx=5)
        
        # Key/Shift Input
        ttk.Label(main_frame, text="Key/Shift:", font=("Arial", 12)).grid(row=3, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(main_frame, width=40)
        self.key_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        self.key_label = ttk.Label(main_frame, text="(Enter shift value)", font=("Arial", 9), foreground="gray")
        self.key_label.grid(row=4, column=1, sticky=tk.W)
        
        # Input Text
        ttk.Label(main_frame, text="Input Text:", font=("Arial", 12)).grid(row=5, column=0, sticky=tk.NW, pady=5)
        self.input_text = scrolledtext.ScrolledText(main_frame, width=60, height=8, wrap=tk.WORD)
        self.input_text.grid(row=5, column=1, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Process", command=self.process_cipher, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_fields, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Exit", command=root.quit, width=15).pack(side=tk.LEFT, padx=5)
        
        # Output Text
        ttk.Label(main_frame, text="Output:", font=("Arial", 12)).grid(row=7, column=0, sticky=tk.NW, pady=5)
        self.output_text = scrolledtext.ScrolledText(main_frame, width=60, height=8, wrap=tk.WORD, state=tk.DISABLED)
        self.output_text.grid(row=7, column=1, pady=5)
        
        # Initialize key field label
        self.update_key_field()
    
    def update_key_field(self):
        """Update the key field label based on selected cipher"""
        cipher = self.cipher_var.get()
        if cipher == "Caesar":
            self.key_label.config(text="(Enter shift value, e.g., 3)")
        elif cipher == "Vigenere":
            self.key_label.config(text="(Enter keyword, e.g., KEY)")
        else:  # Substitution
            self.key_label.config(text="(Enter 26-letter substitution key)")
    
    def process_cipher(self):
        """Process the cipher operation"""
        try:
            # Get input values
            cipher_type = self.cipher_var.get()
            operation = self.operation_var.get()
            key = self.key_entry.get().strip()
            text = self.input_text.get("1.0", tk.END).strip()
            
            # Validate inputs
            if not text:
                messagebox.showerror("Error", "Please enter text to process.")
                return
            
            if not key:
                messagebox.showerror("Error", "Please enter a key/shift value.")
                return
            
            # Process based on cipher type
            result = ""
            if cipher_type == "Caesar":
                try:
                    shift = int(key)
                    result = caesar_cipher(text, shift, operation)
                except ValueError:
                    messagebox.showerror("Error", "Caesar cipher requires a numeric shift value.")
                    return
            
            elif cipher_type == "Vigenere":
                if not key.isalpha():
                    messagebox.showerror("Error", "Vigenère cipher key must contain only letters.")
                    return
                result = vigenere_cipher(text, key, operation)
            
            elif cipher_type == "Substitution":
                key_upper = key.upper()
                if len(key_upper) != 26 or not key_upper.isalpha():
                    messagebox.showerror("Error", "Substitution cipher requires exactly 26 letters.")
                    return
                result = substitution_cipher(text, key_upper, operation)
            
            # Display result
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.output_text.config(state=tk.DISABLED)
            
            # Show success message
            op_text = "encrypted" if operation == "encrypt" else "decrypted"
            messagebox.showinfo("Success", f"Text {op_text} successfully and logged!")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def clear_fields(self):
        """Clear all input and output fields"""
        self.key_entry.delete(0, tk.END)
        self.input_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)


# Main Program Execution
if __name__ == "__main__":
    root = tk.Tk()
    app = CipherGUI(root)
    root.mainloop()
