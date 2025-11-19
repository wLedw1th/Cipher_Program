#cipgher_program.py
# A simple cipher program implementing Caesar, Vigenère, and Substitution ciphers.
# Author: Will Ledwith
# Date Created: 18th November 2025

#Library Imports
import time as time
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


#Menu and Choice Function
def menu():
    print("\n------------------------------")
    print("Menu")
    print("------------------------------")
    print("Cypher Tool Menu:")
    print ("1. Caesar Cipher")
    print ("2. Vigenère Cipher")
    print("3. Substitution Cipher")
    print("4. Exit")
    time.sleep(1)
    print("------------------------------")
    choice = input("Select an option (1-4): ")
    print("------------------------------\n\n")
    time.sleep(1)

    match choice:
        case "1":
            caesar_cipher()
        case "2":
            vigenere_cipher()
        case "3":
            substitution_cipher()
        case "4":
            print("Exiting the program.")
            exit()
        case _:
            print("Invalid choice. Please select a valid option.")
            menu()
        

# Caesar Cipher Function - Encrypts and Decrypts text using a shift value.
def caesar_cipher():
    print("Caesar Cipher selected.")
    time.sleep(2)
    choice = input("Would you like to (e)ncrypt or (d)ecrypt? ").lower()
    match choice:
        case "e":
            shift = int(input("Enter shift value for encryption: "))
            text = input("Enter text to encrypt: ")
            textArray = list(text)
            for i in range(len(textArray)):
                char = textArray[i]
                if char.isalpha():
                    ascii_offset = ord('A') if char.isupper() else ord('a')
                    shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
                    textArray[i] = chr(shifted)
            encrypted_text = ''.join(textArray)
            print("------------------------------\n\n")
            print(f"Encrypted text with shift {shift}: {encrypted_text}")
            print("------------------------------\n\n")
            log_cipher_operation("Caesar Cipher", text, "Encrypted", encrypted_text)


        case "d":
            shift = int(input("Enter shift value for decryption: "))
            text = input("Enter text to decrypt: ")
            textArray = list(text)
            for i in range(len(textArray)):
                char = textArray[i]
                if char.isalpha():
                    ascii_offset = ord('A') if char.isupper() else ord('a')
                    shifted = (ord(char) - ascii_offset - shift) % 26 + ascii_offset
                    textArray[i] = chr(shifted)
            decrypted_text = ''.join(textArray)
            print(f"Decrypted text with shift {shift}: {decrypted_text}")
            print("------------------------------\n\n")
            log_cipher_operation("Caesar Cipher", text, "Decrypted", decrypted_text)
            time.sleep(2)
        case _:
            print("Invalid choice. Returning to menu.")
    menu()


# Vigenère Cipher Function - Encrypts and Decrypts text using a keyword.
def vigenere_cipher():
    print("Vigenère Cipher selected.")
    time.sleep(2)
    choice = input("Would you like to (e)ncrypt or (d)ecrypt? ").lower()
    match choice:
        case "e":
            text = input("Enter text to encrypt: ")
            key = input("Enter encryption key: ")

            textArray = list(text)
            keyArray = list(key)
            keyLength = len(keyArray)
            keyIndex = 0

            for i in range(len(textArray)):
                char = textArray[i]
                if char.isalpha():
                    ascii_offset = ord('A') if char.isupper() else ord('a')
                    shift = ord(keyArray[keyIndex % keyLength].lower()) - ord('a')
                    shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
                    textArray[i] = chr(shifted)
                    keyIndex += 1
            encrypted_text = ''.join(textArray)
            print(f"Encrypted text with key '{key}': {encrypted_text}")
            print("------------------------------\n\n")
            log_cipher_operation("Vigenère Cipher", text, "Encrypted", encrypted_text)
            time.sleep(2)
        
        case "d":
            text = input("Enter text to decrypt: ")
            key = input("Enter decryption key: ")
            textArray = list(text)
            keyArray = list(key)
            keyLength = len(keyArray)
            keyIndex = 0

            for i in range(len(textArray)):
                char = textArray[i]
                if char.isalpha():
                    ascii_offset = ord('A') if char.isupper() else ord('a')
                    shift = ord(keyArray[keyIndex % keyLength].lower()) - ord('a')
                    shifted = (ord(char) - ascii_offset - shift) % 26 + ascii_offset
                    textArray[i] = chr(shifted)
                    keyIndex += 1
            decrypted_text = ''.join(textArray)
            print(f"Decrypted text with key '{key}': {decrypted_text}")
            print("------------------------------\n\n")
            log_cipher_operation("Vigenère Cipher", text, "Decrypted", decrypted_text)
            time.sleep(2)
        case _:
            print("Invalid choice. Returning to menu.")
    menu()


# Substitution Cipher Function - Encrypts and Decrypts text using a substitution key.
def substitution_cipher():
    print("Substitution Cipher selected.")
    time.sleep(2)
    choice = input("Would you like to (e)ncrypt or (d)ecrypt? ").lower()
    match choice:
        case "e":
            text = input("Enter text to encrypt: ")
            key = input("Enter 26-letter substitution key (A-Z): ").upper()
            if len(key) != 26:
                print(f"Error: Key must be exactly 26 letters. You provided {len(key)} letters.")
                menu()
                return
            alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            textArray = list(text)
            keyMap = {alphabet[i]: key[i] for i in range(26)}
            for i in range(len(textArray)):
                char = textArray[i]
                if char.isalpha():
                    is_upper = char.isupper()
                    mapped_char = keyMap[char.upper()]
                    textArray[i] = mapped_char if is_upper else mapped_char.lower()
            encrypted_text = ''.join(textArray)
            print(f"Encrypted text with key '{key}': {encrypted_text}")
            print("------------------------------\n\n")
            log_cipher_operation("Substitution Cipher", text, "Encrypted", encrypted_text)
            time.sleep(2)

        case "d":
            text = input("Enter text to decrypt: ")
            key = input("Enter 26-letter substitution key (A-Z): ").upper()
            if len(key) != 26:
                print(f"Error: Key must be exactly 26 letters. You provided {len(key)} letters.")
                menu()
                return
            alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            textArray = list(text)
            reverseKeyMap = {key[i]: alphabet[i] for i in range(26)}
            for i in range(len(textArray)):
                char = textArray[i]
                if char.isalpha():
                    is_upper = char.isupper()
                    mapped_char = reverseKeyMap[char.upper()]
                    textArray[i] = mapped_char if is_upper else mapped_char.lower()
            decrypted_text = ''.join(textArray)
            print(f"Decrypted text with key '{key}': {decrypted_text}")
            print("------------------------------\n\n")
            log_cipher_operation("Substitution Cipher", text, "Decrypted", decrypted_text)
            time.sleep(2)
        case _:
            print("Invalid choice. Returning to menu.")
            
    menu()

# Main Program Execution
if __name__ == "__main__":
    print("Welcome to the Cipher Program!")
    print ("------------------------------")
    menu()
