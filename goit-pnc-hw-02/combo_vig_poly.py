# Комбіноване шифрування:
#   1) Vigenère Encode (ключ CRYPTOGRAPHY) — працюємо лише з літерами A-Z
#   2) Табличний шифр 6×6 (ключ CRYPTO) — кодує A-Z та 0-9 без втрат
# Зворотне відновлення:
#   1) Табличний Decode 6×6
#   2) Vigenère Decode
#
# Важливо: на відміну від Polybius 5×5, таблиця 6×6 містить усі 26 літер,
# тому не потрібно об’єднувати I/J і немає втрати інформації.

import re
import string

ALPH = string.ascii_uppercase
ALPH36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # 36 символів


# -------------------- VIGENERE (тільки літери) --------------------

def _shift(c: str) -> int:
    return ord(c) - ord("A")


def vigenere_encrypt_letters_only(text: str, key: str) -> str:
    """Шифрує лише літери A-Z. Повертає рядок тільки з літерами (без пробілів/пунктуації)."""
    key = re.sub(r"[^A-Z]", "", key.upper())
    if not key:
        raise ValueError("Ключ Віженера має містити літери A-Z.")

    letters = re.sub(r"[^A-Za-z]", "", text).upper()
    out = []
    for i, ch in enumerate(letters):
        p = _shift(ch)
        k = _shift(key[i % len(key)])
        c = (p + k) % 26
        out.append(chr(c + ord("A")))
    return "".join(out)


def vigenere_decrypt_letters_only(text_letters: str, key: str) -> str:
    """Дешифрує рядок, який містить тільки літери A-Z."""
    key = re.sub(r"[^A-Z]", "", key.upper())
    if not key:
        raise ValueError("Ключ Віженера має містити літери A-Z.")

    text_letters = re.sub(r"[^A-Z]", "", text_letters.upper())
    out = []
    for i, ch in enumerate(text_letters):
        c = _shift(ch)
        k = _shift(key[i % len(key)])
        p = (c - k) % 26
        out.append(chr(p + ord("A")))
    return "".join(out)


def letters_only_normalized(text: str) -> str:
    """Для перевірки: лишаємо тільки літери та робимо upper."""
    return re.sub(r"[^A-Za-z]", "", text).upper()


# -------------------- ТАБЛИЧНИЙ ШИФР 6×6 (A-Z + 0-9) --------------------

def build_table_6x6(keyword: str):
    """
    Будує таблицю 6×6 за ключем.
    - беремо ключ, лишаємо A-Z0-9
    - доповнюємо всіма символами ALPH36, яких ще немає
    Повертає:
      table: список рядків (6 рядків по 6 символів)
      pos: словник символ -> (рядок, стовпець) у діапазоні 1..6
    """
    key = re.sub(r"[^A-Z0-9]", "", keyword.upper())

    seen = set()
    seq = []

    for ch in key + ALPH36:
        if ch in ALPH36 and ch not in seen:
            seen.add(ch)
            seq.append(ch)

    table = [seq[i:i + 6] for i in range(0, 36, 6)]
    pos = {table[r][c]: (r + 1, c + 1) for r in range(6) for c in range(6)}
    return table, pos


def table6x6_encrypt(text: str, keyword: str) -> str:
    """
    Кодує рядок (допускаємо A-Z0-9) у пари цифр "RC" (1..6).
    У нашій задачі сюди потрапляє Віженер-шифротекст (лише A-Z),
    тому все буде кодуватися без втрат.
    """
    _, pos = build_table_6x6(keyword)
    out = []
    for ch in text.upper():
        if ch in ALPH36:
            r, c = pos[ch]
            out.append(f"{r}{c}")
    return " ".join(out)


def table6x6_decrypt(code: str, keyword: str) -> str:
    """Декодує пари цифр назад у символи A-Z0-9."""
    table, _ = build_table_6x6(keyword)

    digits = re.findall(r"\d", code)
    if len(digits) % 2 != 0:
        raise ValueError("Некоректний шифротекст: непарна кількість цифр.")

    out = []
    for i in range(0, len(digits), 2):
        r = int(digits[i]) - 1
        c = int(digits[i + 1]) - 1
        if not (0 <= r < 6 and 0 <= c < 6):
            raise ValueError("Некоректні координати: мають бути 1..6.")
        out.append(table[r][c])

    return "".join(out)


# -------------------- MAIN --------------------

def main() -> None:
    VIG_KEY = "CRYPTOGRAPHY"
    TABLE_KEY = "CRYPTO"

    INPUT_PATH = "data/input.txt"
    OUTPUT_PATH = "data/cipher_combo_vig_table6x6.txt"

    # 1) Зчитуємо відкритий текст
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        plaintext = f.read()

    # 2) Віженер (шифруємо тільки літери)
    vig_cipher_letters = vigenere_encrypt_letters_only(plaintext, VIG_KEY)

    # 3) Табличний 6×6 (кодуємо літери у цифри)
    combo_cipher = table6x6_encrypt(vig_cipher_letters, TABLE_KEY)

    # 4) Записуємо фінальний шифротекст
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(combo_cipher)

    # 5) Зворотне відновлення:
    recovered_vig_letters = table6x6_decrypt(combo_cipher, TABLE_KEY)
    recovered_plain_letters = vigenere_decrypt_letters_only(recovered_vig_letters, VIG_KEY)

    # 6) Перевірка
    original_plain_letters = letters_only_normalized(plaintext)
    ok = recovered_plain_letters == original_plain_letters

    print("=== Комбіноване шифрування: Vigenere -> Табличний 6×6 ===")
    print("Vigenere key:", VIG_KEY)
    print("Table 6×6 key:", TABLE_KEY)
    print("Input file:", INPUT_PATH)
    print("Output file:", OUTPUT_PATH)
    print("Кількість літер у відкритому тексті:", len(original_plain_letters))
    print("Кількість пар у шифротексті:", len(combo_cipher.split()))
    print("Відновлення співпадає з літерною частиною оригіналу:", ok)

    print("\n--- Превʼю ---")
    print("CT (перші 80 пар):", " ".join(combo_cipher.split()[:80]))
    print("Recovered plaintext letters (перші 200):", recovered_plain_letters[:200])

    # Таблиця 6×6 для скріншоту у звіт
    table, _ = build_table_6x6(TABLE_KEY)
    print("\n--- Таблиця 6×6 (ключ CRYPTO) ---")
    for row in table:
        print(" ".join(row))


if __name__ == "__main__":
    main()