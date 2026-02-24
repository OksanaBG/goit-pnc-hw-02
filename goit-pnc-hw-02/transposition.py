# Реалізація колонкової перестановки (простий шифр перестановки)
# Читає текст з data/input.txt
# Записує шифротекст у data/cipher_transposition.txt
# Перевіряє коректність дешифрування

def _key_order(keyword: str) -> list[int]:
    """
    Визначає порядок стовпців відповідно до ключового слова.

    Повертає список, де:
    order[i] = ранг (позиція) i-го стовпця після сортування ключа.

    Якщо у ключі є однакові літери,
    їхній порядок зберігається зліва направо (стабільне сортування).
    """
    kw = keyword.upper()
    pairs = sorted([(ch, i) for i, ch in enumerate(kw)])
    order = [0] * len(kw)
    for rank, (_, idx) in enumerate(pairs):
        order[idx] = rank
    return order


def _inverse_order(order: list[int]) -> list[int]:
    """
    Обернений порядок.

    inv[rank] = індекс стовпця у вихідному тексті
    """
    inv = [0] * len(order)
    for col_idx, rank in enumerate(order):
        inv[rank] = col_idx
    return inv


def columnar_encrypt(text: str, keyword: str, pad: str = "X") -> str:
    """
    Шифрування методом колонкової перестановки.

    1. Текст записується по рядках у таблицю шириною len(keyword)
    2. Якщо потрібно — додається символ доповнення (padding)
    3. Читання відбувається по стовпцях відповідно до відсортованого ключа
    """

    if not keyword.strip():
        raise ValueError("Ключ не може бути порожнім.")

    order = _key_order(keyword)
    k = len(order)

    # Додаємо padding, якщо довжина тексту не кратна довжині ключа
    remainder = (k - (len(text) % k)) % k
    if remainder:
        text += pad * remainder

    # Розбиваємо текст на рядки
    rows = [text[i:i + k] for i in range(0, len(text), k)]

    inv = _inverse_order(order)

    encrypted = []
    for rank in range(k):
        col = inv[rank]
        for row in rows:
            encrypted.append(row[col])

    return "".join(encrypted)


def columnar_decrypt(ciphertext: str, keyword: str) -> str:
    """
    Дешифрування колонкової перестановки.

    Відновлюється таблиця,
    після чого текст зчитується по рядках.
    """

    if not keyword.strip():
        raise ValueError("Ключ не може бути порожнім.")

    order = _key_order(keyword)
    k = len(order)

    if len(ciphertext) % k != 0:
        raise ValueError("Довжина шифротексту повинна бути кратною довжині ключа.")

    rows_count = len(ciphertext) // k
    inv = _inverse_order(order)

    # Створюємо порожню таблицю
    grid = [[""] * k for _ in range(rows_count)]

    index = 0
    for rank in range(k):
        col = inv[rank]
        for r in range(rows_count):
            grid[r][col] = ciphertext[index]
            index += 1

    # Збираємо текст по рядках
    return "".join("".join(row) for row in grid)


def main():
    KEY = "SECRET"

    INPUT_PATH = "data/input.txt"
    OUTPUT_PATH = "data/cipher_transposition.txt"

    # Зчитування відкритого тексту
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        plaintext = f.read()

    # Шифрування
    ciphertext = columnar_encrypt(plaintext, KEY)

    # Запис шифротексту у файл
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(ciphertext)

    # Дешифрування для перевірки
    decrypted = columnar_decrypt(ciphertext, KEY)

    # Обрізаємо padding для порівняння
    decrypted_trimmed = decrypted[:len(plaintext)]

    print("=== Колонкова перестановка ===")
    print("Ключ:", KEY)
    print("Файл вхідного тексту:", INPUT_PATH)
    print("Файл шифротексту:", OUTPUT_PATH)
    print("Дешифрування співпадає з оригіналом:",
          decrypted_trimmed == plaintext)


if __name__ == "__main__":
    main()