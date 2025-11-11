import string
from classicalciphers import Vigenere, Playfair, VigenPlayCipher, ALPHABET
import time
import os

ALPHABET = string.ascii_uppercase

def readfile(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        raw = f.read()
    return ''.join([ch.upper() for ch in raw if ch.isalpha()])

def writefile(path: str, text: str):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)

# -------------------------------
# Runtime dynamic input with fully automatic file handling
# -------------------------------
if __name__ == "__main__":
    print("=== Combined Playfair + Vigenere Cipher with Automatic File Saving ===")
    
    script_folder = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_folder, "input.txt")
    log_file = os.path.join(script_folder, "analysis_log.txt")

    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist. Please create input.txt in the script folder.")
        exit(1)

    while True:
        print("\nOptions:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Choose (1/2/3): ").strip()

        if choice == '1':
            # Ask keys only for encryption
            pf_key = input("Enter Playfair key (letters only, A-Z): ").upper()
            vig_key = input("Enter Vigenere key (min 10 chars): ").upper()
            try:
                plaintext = readfile(input_file)
                cipher = VigenPlayCipher.encrypt(plaintext, pf_key, vig_key)

                output_file = os.path.join(script_folder, "ciphertext.txt")
                writefile(output_file, cipher)
                print(f"Ciphertext saved automatically to {output_file}")

            except Exception as e:
                print("Error during encryption:", e)

        elif choice == '2':
            # Ask keys only for decryption
            pf_key = input("Enter Playfair key (letters only, A-Z): ").upper()
            vig_key = input("Enter Vigenere key (min 10 chars): ").upper()
            try:
                ciphertext = readfile(os.path.join(script_folder, "ciphertext.txt"))
                plain = VigenPlayCipher.decrypt(ciphertext, pf_key, vig_key)

                output_file = os.path.join(script_folder, "plaintext.txt")
                writefile(output_file, plain)
                print(f"Decrypted text saved automatically to {output_file}")

            except Exception as e:
                print("Error during decryption:", e)

        elif choice == '3':
            print("Exiting. Goodbye!")
            break

        else:
            print("Invalid choice! Please enter 1, 2, or 3.")
            continue

        # Log analysis automatically
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"--- Analysis Run at {time.ctime()} ---\n")
            f.write(f"Choice: {choice}\n")
            if choice in ['1','2']:
                f.write(f"Playfair Key: {pf_key}\n")
                f.write(f"Vigenere Key: {vig_key}\n")
            f.write(f"Input file: {input_file}\n")
            f.write(f"Output file: {output_file}\n\n")
        print(f"Analysis details saved to {log_file}")

