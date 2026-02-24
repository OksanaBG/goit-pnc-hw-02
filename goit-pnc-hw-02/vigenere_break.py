import re
import math
from collections import Counter, defaultdict

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
EN_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
    'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
    'P': 1.93, 'B': 1.49, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07
}

def clean_letters(text: str) -> str:
    return re.sub(r'[^A-Z]', '', text.upper())

def index_of_coincidence(s: str) -> float:
    n = len(s)
    if n < 2:
        return 0.0
    cnt = Counter(s)
    num = sum(v*(v-1) for v in cnt.values())
    den = n*(n-1)
    return num / den

def friedman_key_length_estimate(ciphertext: str) -> float:
    s = clean_letters(ciphertext)
    n = len(s)
    if n < 2:
        return 0.0
    ic = index_of_coincidence(s)
    # Класична оцінка для англ. мови (IC≈0.0667), випадкова (≈0.0385)
    k = (0.027 * n) / ((n - 1) * ic - 0.038 * n + 0.065)
    return k

def average_ic_for_keylen(ciphertext: str, keylen: int) -> float:
    s = clean_letters(ciphertext)
    cols = [''.join(s[i::keylen]) for i in range(keylen)]
    return sum(index_of_coincidence(col) for col in cols) / keylen

def kasiski_distances(ciphertext: str, ngram_len: int = 3, top: int = 10):
    s = clean_letters(ciphertext)
    pos = defaultdict(list)
    for i in range(len(s) - ngram_len + 1):
        ng = s[i:i+ngram_len]
        pos[ng].append(i)
    dists = []
    for ng, positions in pos.items():
        if len(positions) >= 3:
            for a, b in zip(positions, positions[1:]):
                dists.append(b - a)
    dists.sort()
    return dists[:top], dists

def gcd_list(nums):
    g = 0
    for x in nums:
        g = math.gcd(g, x)
    return g

def chi_square_for_shift(col: str, shift: int) -> float:
    # Припущення: col зашифровано Цезарем зі зсувом shift (тобто ключова літера)
    # Дешифруємо col (зсуваємо назад) і рахуємо χ² відносно EN частот
    n = len(col)
    if n == 0:
        return float('inf')
    dec = [(chr(((ord(c)-65 - shift) % 26) + 65)) for c in col]
    cnt = Counter(dec)
    chi2 = 0.0
    for letter in ALPH:
        obs = cnt.get(letter, 0)
        exp = n * (EN_FREQ[letter] / 100.0)
        chi2 += (obs - exp) ** 2 / (exp if exp > 0 else 1)
    return chi2

def recover_key_by_freq(ciphertext: str, keylen: int) -> str:
    s = clean_letters(ciphertext)
    cols = [''.join(s[i::keylen]) for i in range(keylen)]
    key = []
    for col in cols:
        best_shift = min(range(26), key=lambda sh: chi_square_for_shift(col, sh))
        key.append(chr(best_shift + 65))
    return ''.join(key)

def main():
    # читаємо файл з невідомим шифротекстом
    with open("data/cipher_vigenere_unknown.txt", "r", encoding="utf-8") as f:
        ct = f.read()

    k_est = friedman_key_length_estimate(ct)
    print("Friedman estimated key length ~", round(k_est, 2))

    print("\nAverage IC by key length (1..20):")
    scores = []
    for k in range(1, 21):
        aic = average_ic_for_keylen(ct, k)
        scores.append((k, aic))
        print(k, "->", round(aic, 4))
    best = sorted(scores, key=lambda x: abs(x[1] - 0.0667))[0]
    print("\nClosest to English IC≈0.0667:", best)

    top_d, all_d = kasiski_distances(ct, 3, top=15)
    print("\nKasiski sample distances (trigrams):", top_d)
    if len(all_d) >= 3:
        g = gcd_list(all_d[:50])
        print("GCD of some distances (hint):", g)

    # Спроба відновити ключ по найкращій довжині
    keylen = best[0]
    guess_key = recover_key_by_freq(ct, keylen)
    print("\nGuessed key (freq/chi2) for keylen", keylen, ":", guess_key)

if __name__ == "__main__":
    main()