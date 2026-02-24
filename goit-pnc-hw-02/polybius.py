# Табличний шифр (квадрат Полібія) з ключовою фразою.
# 1) Читає відкритий текст з data/input.txt
# 2) Кодує текст координатами (рядок, стовпець) у таблиці 5×5
#    (класичний варіант: I та J об'єднані)
# 3) Записує шифротекст у data/cipher_polybius_matrix.txt
# 4) Декодує назад і перевіряє коректність (для літерної частини)

import re

# Алфавіт 5×5 (25 літер), без J (J об'єднуємо з I)
ALPH_25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def build_square(keyword: str):
    """
    Будує 5×5 таблицю (квадрат Полібія) на основі ключа.

    Правила:
    - беремо ключ, лишаємо тільки A-Z
    - замінюємо J -> I
    - додаємо до таблиці літери алфавіту (без J), яких ще немає
    """
    keyword = re.sub(r"[^A-Z]", "", keyword.upper()).replace("J", "I")

    seen = set()
    seq = []

    for ch in keyword + ALPH_25:
        if ch in ALPH_25 and ch not in seen:
            seen.add(ch)
            seq.append(ch)

    # Формуємо 5 рядків по 5 символів
    square = [seq[i:i + 5] for i in range(0, 25, 5)]
    # Координати для швидкого пошуку: літера -> (рядок, стовпець) (1..5)
    pos = {square[r][c]: (r + 1, c + 1) for r in range(5) for c in range(5)}

    return square, pos


def polybius_encrypt(text: str, keyword: str) -> str:
    """
    Шифрування (кодування) квадратом Полібія.

    - Кодуємо тільки літери A-Z
    - J перетворюємо на I
    - Результат: пари цифр "RC" (Row, Column), розділені пробілами
    - Пробіли/пунктуацію в результат не вставляємо (класичний підхід)
    """
    _, pos = build_square(keyword)

    out = []
    for ch in text.upper():
        if "A" <= ch <= "Z":
            if ch == "J":
                ch = "I"
            r, c = pos[ch]
            out.append(f"{r}{c}")

    return " ".join(out)


def polybius_decrypt(code: str, keyword: str) -> str:
    """
    Дешифрування (декодування) квадратом Полібія.

    - З коду беремо тільки цифри
    - Читаємо парами: (рядок, стовпець)
    - Повертаємо рядок з літерами (без пробілів)
    """
    square, _ = build_square(keyword)

    digits = re.findall(r"\d", code)
    if len(digits) % 2 != 0:
        raise ValueError("Некоректний шифротекст: непарна кількість цифр.")

    out = []
    for i in range(0, len(digits), 2):
        r = int(digits[i]) - 1
        c = int(digits[i + 1]) - 1
        if not (0 <= r < 5 and 0 <= c < 5):
            raise ValueError("Некоректні координати у шифротексті (має бути 1..5).")
        out.append(square[r][c])

    return "".join(out)


def letters_only_normalized(text: str) -> str:
    """
    Допоміжна функція для перевірки:
    - залишає тільки літери A-Z
    - переводить у верхній регістр
    - J -> I (бо так працює квадрат Полібія)
    """
    t = re.sub(r"[^A-Za-z]", "", text).upper()
    return t.replace("J", "I")


def main() -> None:
    KEY = "MATRIX"

    INPUT_PATH = "data/input.txt"
    OUTPUT_PATH = "data/cipher_polybius_matrix.txt"

    # 1) Читаємо відкритий текст
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        plaintext = f.read()

    # 2) Шифруємо (кодуємо)
    ciphertext = polybius_encrypt(plaintext, KEY)

    # 3) Записуємо шифротекст у файл
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(ciphertext)

    # 4) Дешифруємо (декодуємо) для перевірки
    decrypted_letters = polybius_decrypt(ciphertext, KEY)

    # 5) Оскільки Polybius кодує тільки літери та не зберігає пробіли/пунктуацію,
    #    перевіряємо коректність лише для "нормалізованої" літерної частини.
    original_letters = letters_only_normalized(plaintext)
    is_ok = decrypted_letters == original_letters

    print("=== Табличний шифр (квадрат Полібія) ===")
    print("Ключ:", KEY)
    print("Файл вхідного тексту:", INPUT_PATH)
    print("Файл шифротексту:", OUTPUT_PATH)
    print("Кількість букв у відкритому тексті:", len(original_letters))
    print("Кількість пар координат у шифротексті:", len(ciphertext.split()))
    print("Декодування співпадає з літерною частиною оригіналу:", is_ok)

    # Превʼю для скріншоту
    print("\n--- Превʼю ---")
    print("CT (перші 80 пар):", " ".join(ciphertext.split()[:80]))
    print("DEC (перші 200 літер):", decrypted_letters[:200])

    # Додатково (за бажанням) можна вивести сам квадрат
    square, _ = build_square(KEY)
    print("\n--- Квадрат 5×5 ---")
    for row in square:
        print(" ".join(row))


if __name__ == "__main__":
    main()