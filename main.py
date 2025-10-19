import os
import binascii
from BIP39 import entropy_to_mnemonic, mnemonic_to_entropy
from BIP32 import mnemonic_to_seed, master_key_from_seed, privkey_to_pubkey


def main():
    print("=== Bitcoin Wallet Practice (TD02) ===")
    print("1. Generate new seed")
    print("2. Import existing mnemonic")
    print("3. Derive BIP32 master")
    print("4. Exit")

    choice = input("Choose an option: ")

    if choice == "1":
        entropy = generate_seed()
        mnemonic = entropy_to_mnemonic(entropy)
        print("\nGenerated mnemonic phrase:")
        print(mnemonic)
    
    elif choice == "2":
        mnemonic = input("\nEnter your mnemonic phrase:\n> ")
        try:
            entropy = mnemonic_to_entropy(mnemonic)
            print(f"\nRecovered entropy (hex): {binascii.hexlify(entropy).decode()}")
            print(f"Entropy length: {len(entropy) * 8} bits\n")
        except ValueError as e:
            print(f"Error: {e}")
    elif choice == "3":
        mnemonic = input("\nEnter your mnemonic phrase (BIP39):\n> ")
        try:
            _ = mnemonic_to_entropy(mnemonic)
        except ValueError as e:
            print(f"Invalid mnemonic: {e}")
            return
        seed = mnemonic_to_seed(mnemonic)
        print(f"\nBIP39 seed (64 bytes) hex:\n{binascii.hexlify(seed).decode()}")
        m_priv, chain_code = master_key_from_seed(seed)
        print(f"\nMaster private key (hex): {binascii.hexlify(m_priv).decode()}")
        print(f"Chain code (hex):         {binascii.hexlify(chain_code).decode()}")
        m_pub = privkey_to_pubkey(m_priv, compressed=True)
        print(f"Master public key (compressed, hex): {binascii.hexlify(m_pub).decode()}\n")
    else:
        print("Goodbye!")

def generate_seed():
    print("\n--- Generating random seed (entropy) ---")

    entropy = os.urandom(16)
    print(f"Raw entropy (bytes): {entropy}")
    print(f"Entropy (hex): {binascii.hexlify(entropy).decode()}")
    print(f"Entropy length: {len(entropy) * 8} bits\n")
    return entropy


if __name__ == "__main__":
    main()