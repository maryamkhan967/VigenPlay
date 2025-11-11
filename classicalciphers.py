import string
from typing import List

ALPHABET = string.ascii_uppercase  # 'A'..'Z'

# VIGENÈRE
# -------------------------------
class Vigenere:
    @staticmethod
    def __extend_key(key: str, length: int) -> str:
        k = key.upper()
        if len(k) < length:
            k = (k * ((length // len(k)) + 1))[:length]
        return k

    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """Encrypt plaintext (A-Z only) using Vigenère key (letters)."""
        plaintext = plaintext.upper()
        key_ext = Vigenere.__extend_key(key, len(plaintext))
        res = []
        for p, k in zip(plaintext, key_ext):
            pi = ALPHABET.index(p)
            ki = ALPHABET.index(k)
            ci = (pi + ki) % 26
            res.append(ALPHABET[ci])
        return ''.join(res)

    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        ciphertext = ciphertext.upper()
        key_ext = Vigenere.__extend_key(key, len(ciphertext))
        res = []
        for c, k in zip(ciphertext, key_ext):
            ci = ALPHABET.index(c)
            ki = ALPHABET.index(k)
            pi = (ci - ki) % 26
            res.append(ALPHABET[pi])
        return ''.join(res)

# -------------------------------
# PLAYFAIR (5x5) — J merged with I
# -------------------------------
class Playfair:
    @staticmethod
    def __prepare_key(key: str) -> str:
        """Return 25-letter key table as string (A-Z with J removed)"""
        k = ''.join([c for c in key.upper() if c.isalpha()]).replace('J', 'I')
        seen = []
        for ch in k:
            if ch not in seen:
                seen.append(ch)
        for ch in ALPHABET:
            if ch == 'J':  # merge J into I
                continue
            if ch not in seen:
                seen.append(ch)
        return ''.join(seen[:25])

    @staticmethod
    def build_table(key: str) -> str:
        """Public: build table (alias)"""
        return Playfair.__prepare_key(key)

    @staticmethod
    def __pairs_from_message(message: str) -> List[str]:
        """Pad message into digrams according to Playfair rules (replace J->I)."""
        m = message.upper().replace('J', 'I')
        m = ''.join([c for c in m if c.isalpha()])  # keep only letters
        out = []
        i = 0
        while i < len(m):
            a = m[i]
            b = m[i+1] if i+1 < len(m) else ''
            if b == '':
                out.append(a + 'X')
                i += 1
            elif a == b:
                out.append(a + 'X')
                i += 1
            else:
                out.append(a + b)
                i += 2
        return out

    @staticmethod
    def __pos(table: str, ch: str):
        
        if ch == 'J':
            ch = 'I'
        
        idx = table.index(ch)
        return (idx // 5, idx % 5)

    @staticmethod
    def __ch(table: str, row: int, col: int):
        return table[row*5 + col]

    @staticmethod
    def __substitute_pair(p: str, table: str, mode: int) -> str:
        # mode = +1 for encrypt, -1 for decrypt
        (r1, c1) = Playfair.__pos(table, p[0])
        (r2, c2) = Playfair.__pos(table, p[1])
        if r1 == r2:
            # same row
            c1n = (c1 + mode) % 5
            c2n = (c2 + mode) % 5
            return Playfair.__ch(table, r1, c1n) + Playfair.__ch(table, r2, c2n)
        elif c1 == c2:
            # same column
            r1n = (r1 + mode) % 5
            r2n = (r2 + mode) % 5
            return Playfair.__ch(table, r1n, c1) + Playfair.__ch(table, r2n, c2)
        else:
            # rectangle
            return Playfair.__ch(table, r1, c2) + Playfair.__ch(table, r2, c1)

    @staticmethod
    def encrypt(plaintext: str, key_table: str) -> str:
        """Encrypt plaintext (A-Z) using Playfair key_table (string 25 chars)."""
        pairs = Playfair.__pairs_from_message(plaintext)
        return ''.join([Playfair.__substitute_pair(p, key_table, +1) for p in pairs])

    @staticmethod
    def decrypt(ciphertext: str, key_table: str) -> str:
        """Decrypt ciphertext (even length) using Playfair key_table."""
        # split into pairs
        c = ''.join([ch for ch in ciphertext.upper() if ch.isalpha()])
        if len(c) % 2 != 0:
            raise ValueError("Playfair ciphertext length must be even.")
        pairs = [c[i:i+2] for i in range(0, len(c), 2)]
        return ''.join([Playfair.__substitute_pair(p, key_table, -1) for p in pairs])

# -------------------------------
# COMBINED: Vigenere after Playfair (Playfair -> Vigenere)
# -------------------------------
class VigenPlayCipher:
    """
    Combined cipher:
      1) Playfair encrypt with key1 (any length) -> intermediate (letters A-Z but J mapped to I)
      2) Vigenere encrypt intermediate with key2 (must be >=10 chars)
    Decrypt reverses order and removes Playfair padding 'X'.
    """

    @staticmethod
    def __remove_playfair_padding(text: str) -> str:
        """Remove 'X' inserted between repeated letters and at the end if it was padding."""
        result = []
        i = 0
        while i < len(text):
            a = text[i]
            # Skip 'X' between repeated letters
            if i+2 < len(text) and text[i+1] == 'X' and text[i] == text[i+2]:
                result.append(a)
                i += 2  # skip the X
            # Skip trailing 'X' if at the end (odd-length padding)
            elif i+1 == len(text) - 1 and text[i+1] == 'X':
                result.append(a)
                i += 2
            else:
                result.append(a)
                i += 1
        return ''.join(result)

    @staticmethod
    def encrypt(plaintext: str, playfair_key: str, vigenere_key: str) -> str:
        if len(vigenere_key) < 10:
            raise ValueError("Vigenere key must be at least 10 characters (project requirement).")
        table = Playfair.build_table(playfair_key)
        stage1 = Playfair.encrypt(plaintext, table)    # letters A-Z (no J)
        stage2 = Vigenere.encrypt(stage1, vigenere_key)
        return stage2

    @staticmethod
    def decrypt(ciphertext: str, playfair_key: str, vigenere_key: str) -> str:
        if len(vigenere_key) < 10:
            raise ValueError("Vigenere key must be at least 10 characters (project requirement).")
        stage1 = Vigenere.decrypt(ciphertext, vigenere_key)
        table = Playfair.build_table(playfair_key)
        stage2 = Playfair.decrypt(stage1, table)
        return VigenPlayCipher.__remove_playfair_padding(stage2)
