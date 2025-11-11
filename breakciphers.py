# # breakciphers.py
# # Attack & analysis tools for VigenPlayCipher (Playfair -> Vigenere)
# # Includes: Kasiski, Friedman (IC), frequency-based Vigenere recovery,
# # hill-climb Playfair breaker (simple trigram/word scoring), known-plaintext helper.
# # Note: heuristic approaches; results vary with text length and keys.

import math
import random
import time
from collections import Counter, defaultdict
from classicalciphers import Vigenere, Playfair, VigenPlayCipher, ALPHABET

# ---------------------------
# English frequency table (A-Z)
# ---------------------------
ENGLISH_FREQ = {
 'A':0.08167,'B':0.01492,'C':0.02782,'D':0.04253,'E':0.12702,'F':0.02228,'G':0.02015,
 'H':0.06094,'I':0.06966,'J':0.00153,'K':0.00772,'L':0.04025,'M':0.02406,'N':0.06749,
 'O':0.07507,'P':0.01929,'Q':0.00095,'R':0.05987,'S':0.06327,'T':0.09056,'U':0.02758,
 'V':0.00978,'W':0.0236,'X':0.0015,'Y':0.01974,'Z':0.00074
}

COMMON_TRIGRAMS = ['THE','AND','ING','ENT','ION','HER','FOR','THA','NDE','HAT','ERE','TED','TER','ERS']

# ---------------------------
# Utilities
# ---------------------------
def letters_only(s: str) -> str:
    return ''.join([c for c in s.upper() if c.isalpha()])

def frequency(s: str):
    s = letters_only(s)
    n = len(s)
    if n == 0: return {ch:0.0 for ch in ALPHABET}
    c = Counter(s)
    return {ch: c.get(ch,0)/n for ch in ALPHABET}

def letterscount(s: str):
    s = letters_only(s)
    c = Counter(s)
    return {ch: c.get(ch,0) for ch in ALPHABET}

def index_of_coincidence(s: str) -> float:
    """Compute IC for string s."""
    counts = letterscount(s)
    n = sum(counts.values())
    if n <= 1: return 0.0
    tot = sum([v*(v-1) for v in counts.values()])
    return tot / (n*(n-1))

# ---------------------------
# KASISKI EXAMINATION
# ---------------------------
def kasiski_distances(ciphertext: str, min_len=3, max_len=5):
    """Return dictionary: repeated_substring -> list of distances between occurrences."""
    s = letters_only(ciphertext)
    dists = {}
    n = len(s)
    for L in range(min_len, max_len+1):
        seen = {}
        for i in range(n - L + 1):
            sub = s[i:i+L]
            if sub in seen:
                # add distance from previous occurrence(s)
                for prev in seen[sub]:
                    dists.setdefault(sub,[]).append(i - prev)
                seen[sub].append(i)
            else:
                seen[sub] = [i]
    return dists

def kasiski_gcds(ciphertext: str):
    d = kasiski_distances(ciphertext)
    gcds = []
    for sub, distlist in d.items():
        for dist in distlist:
            gcds.append(dist)
    # compute counts of gcds / their factors
    factor_counts = Counter()
    for val in gcds:
        # factor small ints 2..20
        for f in range(2, 31):
            if val % f == 0:
                factor_counts[f] += 1
    return factor_counts.most_common()

# ---------------------------
# FRIEDMAN (IC) estimate
# ---------------------------
ENGLISH_IC = 0.0667
RANDOM_IC = 1/26

def friedman_estimate(ciphertext: str):
    s = letters_only(ciphertext)
    ic = index_of_coincidence(s)
    n = len(s)
    if n <= 1: return 1
    # Standard Friedman formula
    est_k = (ENGLISH_IC - RANDOM_IC) / (ic - RANDOM_IC) if (ic - RANDOM_IC) != 0 else 1
    # floor to nearest int >=1 and <=25
    try:
        k = max(1, int(round(est_k)))
    except:
        k = 1
    if k > 25: k = 25
    return k, ic

# ---------------------------
# Guess Vigenere key length (combine Kasiski & Friedman)
# ---------------------------
def find_vigenere_key_lengths(ciphertext: str, top=4):
    """Return candidate key lengths (sorted) using Kasiski factors and Friedman estimate."""
    kcandidates = Counter()
    # Kasiski factors
    factors = kasiski_gcds(ciphertext)
    for f, cnt in factors[:20]:
        if 1 < f <= 25: kcandidates[f] += cnt
    # Friedman
    k_fried, ic = friedman_estimate(ciphertext)
    kcandidates[k_fried] += 2
    if len(kcandidates) == 0:
        # fallback
        return [k_fried]
    # return top keys
    return [k for k,_ in kcandidates.most_common(top)]

# ---------------------------
# Recover Vigenere key given key length (frequency analysis on columns)
# ---------------------------
def score_shift_on_column(column_text: str, shift: int) -> float:
    """Shift column by `shift` (i.e., Caesar decrypt with shift) and compute correlation with English freq."""
    # Apply Caesar shift (decrypt): shifted = (letter - shift)
    s = ''
    for ch in column_text:
        if ch.isalpha():
            idx = ALPHABET.index(ch)
            dec = ALPHABET[(idx - shift) % 26]
            s += dec
    freq = frequency(s)
    # correlation score: sum(freq[ch] * ENGLISH_FREQ[ch])
    score = sum(freq[ch] * ENGLISH_FREQ.get(ch, 0) for ch in ALPHABET)
    return score

def recover_vigenere_key(ciphertext: str, key_len: int):
    """Recover Vigenere key (best shifts) using frequency correlation per column."""
    s = letters_only(ciphertext)
    key_chars = []
    for i in range(key_len):
        # build column with letters at positions i, i+key_len, ...
        col = ''.join([s[j] for j in range(i, len(s), key_len)])
        best = None, -999
        for shift in range(26):
            sc = score_shift_on_column(col, shift)
            if sc > best[1]:
                best = (shift, sc)
        # best shift corresponds to key letter: shift means subtracting shift in decrypt,
        # thus key letter index = shift (because decrypt uses -key)
        key_chars.append(ALPHABET[best[0]])
    return ''.join(key_chars)

# ---------------------------
# Playfair breaker (hillclimbing)
# ---------------------------
def trigram_count(text: str):
    t = text.upper()
    cnt = 0
    for g in COMMON_TRIGRAMS:
        cnt += t.count(g)
    return cnt

def english_word_score(text: str, wordlist=['THE','AND','TO','OF','IN','IS','IT','YOU']):
    # count occurrences of common short words
    t = text.upper()
    score = 0
    for w in wordlist:
        score += t.count(w)
    return score

def playfair_score(plaintext_candidate: str):
    # combined heuristic: trigram_count + word_score + small length penalty
    return trigram_count(plaintext_candidate) * 2 + english_word_score(plaintext_candidate)

def random_playfair_key():
    alph = ''.join([c for c in ALPHABET if c != 'J'])
    l = list(alph)
    random.shuffle(l)
    return ''.join(l)

def mutate_playfair_key(key: str):
    # swap two letters (very common), occasionally reverse, sometimes swap rows/columns
    k = list(key)
    r = random.random()
    if r < 0.8:
        i = random.randrange(25)
        j = random.randrange(25)
        k[i], k[j] = k[j], k[i]
    elif r < 0.88:
        k.reverse()
    elif r < 0.94:
        # swap two rows
        r1 = random.randrange(5)
        r2 = random.randrange(5)
        for c in range(5):
            k[r1*5 + c], k[r2*5 + c] = k[r2*5 + c], k[r1*5 + c]
    else:
        # swap two columns
        c1 = random.randrange(5)
        c2 = random.randrange(5)
        for r in range(5):
            k[r*5 + c1], k[r*5 + c2] = k[r*5 + c2], k[r*5 + c1]
    return ''.join(k)

def break_playfair_via_hillclimb(ciphertext_playfair: str, restarts=20, iterations=2000):
    """
    Attempt to break Playfair ciphertext (which is the intermediate after Playfair).
    Uses hillclimbing with multiple random restarts, heuristic scoring by trigram+words.
    Returns best plaintext found and its key table.
    """
    best_plain = ''
    best_key = None
    best_score = -1e9

    for r in range(restarts):
        # start with random key or slightly biased key
        parent_key = random_playfair_key()
        parent_plain = Playfair.decrypt(ciphertext_playfair, parent_key)
        parent_score = playfair_score(parent_plain)

        for i in range(iterations):
            child_key = mutate_playfair_key(parent_key)
            child_plain = Playfair.decrypt(ciphertext_playfair, child_key)
            child_score = playfair_score(child_plain)
            if child_score > parent_score or random.random() < 0.001:
                parent_key = child_key
                parent_score = child_score
            if parent_score > best_score:
                best_score = parent_score
                best_plain = Playfair.decrypt(ciphertext_playfair, parent_key)
                best_key = parent_key
        # small print to show progress can be enabled if desired
    return best_plain, best_key, best_score

# ---------------------------
# Combined breaker pipeline
# ---------------------------
def break_vigenplay(ciphertext: str, verbose=True, time_limit=120):
    """
    Attempt to break combined Playfair->Vigenere cipher:
      1) Guess Vigenere key lengths (Kasiski+Friedman)
      2) For each candidate length, recover key by frequency analysis per column
      3) Decrypt Vigenere to obtain Playfair ciphertext
      4) Break Playfair via hillclimb
    Returns best plaintext found and keys (vigenere_key, playfair_key)
    """
    start = time.time()
    ct = ''.join([c for c in ciphertext.upper() if c.isalpha()])
    candidates = find_vigenere_key_lengths(ct, top=6)
    # always include some fallback lengths
    for k in range(1,6):
        if k not in candidates:
            candidates.append(k)
    best_overall = {'plain':'', 'vkey':None, 'pkey':None, 'score':-1e9, 'time':0}
    tried = 0
    for keylen in candidates:
        if time.time() - start > time_limit:
            break
        tried += 1
        vkey_guess = recover_vigenere_key(ct, keylen)
        # Decrypt Vigenere with this guessed key
        intermediate = Vigenere.decrypt(ct, vkey_guess)
        # Now try to break Playfair
        plain_try, pkey_try, score_try = break_playfair_via_hillclimb(intermediate, restarts=30, iterations=1500)
        if verbose:
            print(f"[trial {tried}] keylen {keylen} -> vkey {vkey_guess} ; playfair_best_score {score_try}")
        if score_try > best_overall['score']:
            best_overall.update({'plain': plain_try, 'vkey': vkey_guess, 'pkey': pkey_try, 'score': score_try, 'time': time.time()-start})
    return best_overall

# ---------------------------
# Known-plaintext helper
# ---------------------------
def known_plaintext_recover_vigenere(ciphertext: str, known_plain: str, playfair_key: str, align_pos: int=0):
    """
    If attacker *knows* a plaintext fragment AND the attacker *knows* the Playfair key (or
    can compute Playfair.encrypt(known_plain) to get the intermediate), then the attacker can
    easily deduce the Vigenere key fragment that maps that intermediate to the ciphertext fragment.

    Inputs:
      - ciphertext: final ciphertext (Playfair->Vigenere)
      - known_plain: plaintext fragment (letters A-Z)
      - playfair_key: Playfair key string (used to compute Playfair of known_plain)
      - align_pos: index into ciphertext where known_plain maps in final ciphertext

    Returns:
      recovered_key_fragment (string) corresponding to fragment length
    """
    # compute intermediate = Playfair.encrypt(known_plain, table)
    table = Playfair.build_table(playfair_key)
    intermediate = Playfair.encrypt(known_plain, table)
    # slice ciphertext at alignment
    ct = ''.join([c for c in ciphertext.upper() if c.isalpha()])
    if align_pos + len(intermediate) > len(ct):
        raise ValueError("Alignment out of range of ciphertext")
    ct_seg = ct[align_pos:align_pos+len(intermediate)]
    # key fragment letters: for each position k: key = (ct - intermediate) mod26
    frag = []
    for ic, cc in zip(intermediate, ct_seg):
        k_idx = (ALPHABET.index(cc) - ALPHABET.index(ic)) % 26
        frag.append(ALPHABET[k_idx])
    return ''.join(frag)

# ---------------------------
# Example usage & demo
# ---------------------------
def demo_run():
    # Demo: encrypt, decrypt, break
    plaintext = "DEFENDTHEEASTWALLOFTHECASTLE"  # test message
    # choose keys meeting requirement (vigenere key >= 10 chars)
    playfair_key = "MONARCHY"
    vigenere_key = "FORTIFICATION"  # 12 chars

    print("Plain:", plaintext)
    ct = VigenPlayCipher.encrypt(plaintext, playfair_key, vigenere_key)
    print("Cipher (VigenPlay):", ct)

    # Decrypt normally
    pt = VigenPlayCipher.decrypt(ct, playfair_key, vigenere_key)
    print("Decrypted (correct keys):", pt)

    # Attempt to break
    print("\nAttempting automated break (may take time)...")
    start = time.time()
    result = break_vigenplay(ct, verbose=True, time_limit=90)
    end = time.time()
    print("\n--- BREAK RESULT ---")
    print("Time spent:", end - start)
    print("Best Vigenere key guess:", result['vkey'])
    print("Best Playfair key found:", result['pkey'])
    print("Recovered plaintext candidate:", result['plain'])
    print("Score:", result['score'])

    # Known-plaintext example (assumes playfair_key known)
    print("\nKnown-plaintext example (assume Playfair key known):")
    known = "DEFEND"
    # align_pos we assume attacker knows where this maps (demo uses 0)
    frag = known_plaintext_recover_vigenere(ct, known, playfair_key, align_pos=0)
    print("Recovered vigenere fragment for known plaintext:", frag)


if __name__ == "__main__":
    demo_run()
