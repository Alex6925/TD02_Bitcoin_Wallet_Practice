import os
import binascii
from BIP39 import entropy_to_mnemonic, mnemonic_to_entropy
from BIP32 import mnemonic_to_seed, master_key_from_seed, privkey_to_pubkey, derive_child_private_key, derive_path


def main():
    print("=== Bitcoin Wallet Practice (TD02) ===")
    print("1. Generate new seed")
    print("2. Import existing mnemonic")
    print("3. Derive BIP32 master")
    print("4. Derive BIP32 child key (m/N)")
    print("5. Derive BIP32 path (m/N/M...)")
    print("6. Exit")

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
        mnemonic = input("\nEnter your mnemonic phrase:\n> ")
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
    elif choice == "4":
        mnemonic = input("\nEnter your mnemonic phrase:\n> ")
        index = int(input("Enter child index: "))
        seed = mnemonic_to_seed(mnemonic)
        m_priv, m_chain = master_key_from_seed(seed)

        child_priv, child_chain = derive_child_private_key(m_priv, m_chain, index)
        child_pub = privkey_to_pubkey(child_priv, compressed=True)

        print(f"\nChild index: m/{index}")
        print(f"Child private key (hex): {binascii.hexlify(child_priv).decode()}")
        print(f"Child chain code (hex):  {binascii.hexlify(child_chain).decode()}")
        print(f"Child public key (hex):  {binascii.hexlify(child_pub).decode()}\n")
    elif choice == "5":
        mnemonic = input("\nEnter your mnemonic phrase (BIP39):\n> ")
        path = input("Enter derivation path (ex: m/0/1'/2): ")
        seed = mnemonic_to_seed(mnemonic)
        m_priv, m_chain = master_key_from_seed(seed)

        try:
            child_priv, child_chain = derive_path(path, m_priv, m_chain)
            child_pub = privkey_to_pubkey(child_priv, compressed=True)

            print(f"\nDerivation path: {path}")
            print(f"Final private key (hex): {binascii.hexlify(child_priv).decode()}")
            print(f"Final chain code (hex):  {binascii.hexlify(child_chain).decode()}")
            print(f"Final public key (hex):  {binascii.hexlify(child_pub).decode()}\n")

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