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

def mnemonic_to_entropy(mnemonic: str):
    wordlist = load_wordlist()
    words = mnemonic.strip().split()

    if len(words) not in [12, 15, 18, 21, 24]:
        raise ValueError("Invalid mnemonic length")

    bits = ""
    for word in words:
        if word not in wordlist:
            raise ValueError(f"Word '{word}' not found in BIP39 wordlist")
        index = wordlist.index(word)
        bits += bin(index)[2:].zfill(11)

    total_bits = len(bits)
    checksum_length = total_bits // 33
    entropy_length = total_bits - checksum_length

    entropy_bits = bits[:entropy_length]
    checksum_bits = bits[-checksum_length:]

    entropy_int = int(entropy_bits, 2)
    entropy = entropy_int.to_bytes(entropy_length // 8, byteorder="big")

    hash_bits = bin(int.from_bytes(hashlib.sha256(entropy).digest(), byteorder="big"))[2:].zfill(256)
    expected_checksum = hash_bits[:checksum_length]

    if checksum_bits != expected_checksum:
        raise ValueError("Invalid checksum — mnemonic might be incorrect.")

    return entropy