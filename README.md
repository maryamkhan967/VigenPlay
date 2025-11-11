# 🧩 VigenPlay: Hybrid Classical Cipher (Vigenère + Playfair)

## 🔍 Overview
**VigenPlay** is a hybrid classical encryption system that combines the strengths of two iconic ciphers — **Vigenère** and **Playfair** — to achieve a more secure and complex encryption process.  

This project was developed as part of a **Network and Information Security** course. Its goal is to explore how combining multiple substitution ciphers can increase resistance to classical cryptanalysis methods while maintaining educational transparency.

The encryption process occurs in two stages:
1. **Playfair Cipher:** Converts plaintext into digraphs and substitutes each pair using a 5x5 matrix.
2. **Vigenère Cipher:** Applies a polyalphabetic substitution to the Playfair output using a keyword (10+ characters).

The result is a cipher that is both **educational and secure** for learning purposes — demonstrating layered encryption design and the importance of key complexity.

The implementation, analysis, and attack experiments are documented in the attached project report *.

---

## ✨ Key Features

### 🔐 Dual Encryption Mechanism  
Combines **Playfair** (digraph substitution) and **Vigenère** (polyalphabetic substitution) for layered security.

### 🧠 Classical Cryptanalysis Resistance  
Harder to break using frequency analysis, Kasiski, or Index of Coincidence due to hybrid nature.

### ⚙️ Modular Python Implementation  
Includes well-structured modules:
- `classicalciphers.py` — Core cipher algorithms.  
- `classicalciphers_runtime.py` — Command-line interface for encryption/decryption.  
- `breakciphers.py` — Automated breaker and analysis tools.

### 🧮 Cryptanalysis Tools  
Implements **Kasiski**, **Friedman**, and **Hill-Climbing** methods for testing cipher resilience.

### 🧾 Example Runs  
Contains example input text files for quick testing.

---

## 🏗️ Cipher Architecture

**Stage 1: Playfair Cipher**
- Generates a 5x5 matrix key.
- Encrypts plaintext in digraphs.
- Handles repeated letters and padding (`X`).

**Stage 2: Vigenère Cipher**
- Uses long key (≥10 chars).
- Shifts characters based on key values.
- Enhances diffusion and complexity.

**Decryption:**  
The process is reversed — first Vigenère decryption, then Playfair decryption — to recover plaintext accurately.

---


# Choose option 1 (Encrypt)
# Enter plaintext, Playfair key, and Vigenère key
