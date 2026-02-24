import string

ALPH = string.ascii_uppercase

def _shift(c: str) -> int:
    return ord(c) - ord('A')

def vigenere_encrypt(text: str, key: str) -> str:
    key = ''.join([k for k in key.upper() if k in ALPH])
    out = []
    j = 0
    for ch in text:
        up = ch.upper()
        if up in ALPH:
            p = _shift(up)
            k = _shift(key[j % len(key)])
            c = (p + k) % 26
            enc = chr(c + ord('A'))
            out.append(enc if ch.isupper() else enc.lower())
            j += 1
        else:
            out.append(ch)
    return ''.join(out)

if __name__ == "__main__":
    KEY = "CRYPTOGRAPHY"

    # 🔹 Читання з файлу
    with open("data/input.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()

    ciphertext = vigenere_encrypt(plaintext, KEY)

    # 🔹 Запис у файл
    with open("data/cipher_vigenere_unknown.txt", "w", encoding="utf-8") as f:
        f.write(ciphertext)

    print("Encryption complete.")
    print("Ciphertext saved to data/cipher_vigenere_unknown.txt")