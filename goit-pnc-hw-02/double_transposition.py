# Подвійна колонкова перестановка (Double Columnar Transposition)
# 1) Читає відкритий текст з data/input.txt
# 2) Шифрує колонковою перестановкою з ключем KEY1
# 3) Шифрує результат ще раз колонковою перестановкою з ключем KEY2
# 4) Записує шифротекст у data/cipher_double_transposition.txt
# 5) Дешифрує у зворотному порядку (KEY2 -> KEY1) і перевіряє коректність

def _key_order(keyword: str) -> list[int]:
    """
    Формує порядок стовпців за ключовим словом.

    Повертає список order:
    order[i] = ранг (позиція) i-го стовпця після сортування ключа.

    Якщо у ключі повторюються літери, порядок зліва направо зберігається
    (стабільне сортування через індекс).
    """
    kw = keyword.upper()
    pairs = sorted([(ch, i) for i, ch in enumerate(kw)])
    order = [0] * len(kw)
    for rank, (_, idx) in enumerate(pairs):
        order[idx] = rank
    return order


def _inverse_order(order: list[int]) -> list[int]:
    """
    Обернений порядок:
    inv[rank] = індекс стовпця в оригінальному розташуванні.
    """
    inv = [0] * len(order)
    for col_idx, rank in enumerate(order):
        inv[rank] = col_idx
    return inv


def columnar_encrypt(text: str, keyword: str, pad: str = "X") -> str:
    """
    Шифрування колонковою перестановкою.

    1) Записуємо текст по рядках у таблицю шириною len(keyword)
    2) Додаємо padding, якщо потрібно, щоб заповнити останній рядок
    3) Зчитуємо по стовпцях у порядку, заданому відсортованим ключем
    """
    if not keyword or not keyword.strip():
        raise ValueError("Ключ не може бути порожнім.")

    order = _key_order(keyword)
    k = len(order)

    # Додаємо padding, якщо довжина тексту не кратна довжині ключа
    remainder = (k - (len(text) % k)) % k
    if remainder:
        text += pad * remainder

    rows = [text[i:i + k] for i in range(0, len(text), k)]
    inv = _inverse_order(order)

    out = []
    for rank in range(k):
        col = inv[rank]
        for row in rows:
            out.append(row[col])

    return "".join(out)


def columnar_decrypt(ciphertext: str, keyword: str) -> str:
    """
    Дешифрування колонкової перестановки.

    1) Знаємо ширину таблиці = len(keyword)
    2) Відновлюємо таблицю, заповнюючи стовпці у порядку відсортованого ключа
    3) Зчитуємо таблицю по рядках
    """
    if not keyword or not keyword.strip():
        raise ValueError("Ключ не може бути порожнім.")

    order = _key_order(keyword)
    k = len(order)

    if len(ciphertext) % k != 0:
        raise ValueError("Довжина шифротексту повинна бути кратною довжині ключа.")

    rows_count = len(ciphertext) // k
    inv = _inverse_order(order)

    grid = [[""] * k for _ in range(rows_count)]

    idx = 0
    for rank in range(k):
        col = inv[rank]
        for r in range(rows_count):
            grid[r][col] = ciphertext[idx]
            idx += 1

    return "".join("".join(row) for row in grid)


def double_encrypt(text: str, key1: str, key2: str, pad: str = "X") -> str:
    """
    Подвійне шифрування:
    1) колонкова перестановка з key1
    2) колонкова перестановка з key2
    """
    step1 = columnar_encrypt(text, key1, pad=pad)
    step2 = columnar_encrypt(step1, key2, pad=pad)
    return step2


def double_decrypt(ciphertext: str, key1: str, key2: str) -> str:
    """
    Подвійне дешифрування (зворотний порядок ключів):
    1) розшифрування колонкової перестановки з key2
    2) розшифрування колонкової перестановки з key1
    """
    step1 = columnar_decrypt(ciphertext, key2)
    step2 = columnar_decrypt(step1, key1)
    return step2


def main() -> None:
    KEY1 = "SECRET"
    KEY2 = "CRYPTO"

    INPUT_PATH = "data/input.txt"
    OUTPUT_PATH = "data/cipher_double_transposition.txt"

    # 1) Зчитуємо відкритий текст
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        plaintext = f.read()

    # 2) Подвійне шифрування
    ciphertext = double_encrypt(plaintext, KEY1, KEY2, pad="X")

    # 3) Записуємо шифротекст
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(ciphertext)

    # 4) Подвійне дешифрування для перевірки
    decrypted_padded = double_decrypt(ciphertext, KEY1, KEY2)

    # 5) Прибираємо padding (просто обрізаємо до довжини оригіналу)
    decrypted = decrypted_padded[:len(plaintext)]

    print("=== Подвійна колонкова перестановка ===")
    print("Ключ 1:", KEY1)
    print("Ключ 2:", KEY2)
    print("Файл вхідного тексту:", INPUT_PATH)
    print("Файл шифротексту:", OUTPUT_PATH)
    print("Довжина відкритого тексту:", len(plaintext))
    print("Довжина шифротексту:", len(ciphertext))
    print("Дешифрування співпадає з оригіналом:", decrypted == plaintext)

    # Невеликий превʼю, щоб зручно робити скріншот у звіт
    print("\n--- Превʼю (перші 200 символів) ---")
    print("CT :", ciphertext[:200])
    print("DEC:", decrypted[:200])


if __name__ == "__main__":
    main()