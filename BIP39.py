import hashlib
import binascii

def load_wordlist():
    with open("english.txt", "r", encoding="utf-8") as f:
        return [word.strip() for word in f.readlines()]

def entropy_to_mnemonic(entropy: bytes):
    wordlist = load_wordlist()

    entropy_bits = bin(int.from_bytes(entropy, byteorder="big"))[2:].zfill(len(entropy) * 8)

    hash_bytes = hashlib.sha256(entropy).digest()
    hash_bits = bin(int.from_bytes(hash_bytes, byteorder="big"))[2:].zfill(256)

    checksum_length = len(entropy) * 8 // 32
    checksum = hash_bits[:checksum_length]

    bits = entropy_bits + checksum

    chunks = [bits[i:i+11] for i in range(0, len(bits), 11)]

    words = [wordlist[int(chunk, 2)] for chunk in chunks]

    mnemonic = " ".join(words)
    return mnemonic