import os
import binascii
from BIP39 import entropy_to_mnemonic, mnemonic_to_entropy

def main():
    print("=== Bitcoin Wallet Practice (TD02) ===")
    print("1. Generate new seed")
    print("2. Import existing mnemonic")
    print("3. Exit")

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