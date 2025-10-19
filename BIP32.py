import hmac, hashlib, binascii
from ecdsa import SigningKey, SECP256k1

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        salt,
        2048,
        dklen=64,
    )

def master_key_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def privkey_to_pubkey(privkey: bytes, compressed: bool = True) -> bytes:
    
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    x_bytes = x.to_bytes(32, "big")
    if not compressed:
        y_bytes = y.to_bytes(32, "big")
        return b"\x04" + x_bytes + y_bytes
    prefix = b"\x02" if (y % 2 == 0) else b"\x03"
    return prefix + x_bytes

def derive_child_private_key(parent_privkey: bytes, parent_chaincode: bytes, index: int) -> tuple[bytes, bytes]:
    
    hardened = index >= 0x80000000

    if hardened:
        data = b"\x00" + parent_privkey + index.to_bytes(4, "big")
    else:
        parent_pubkey = privkey_to_pubkey(parent_privkey, compressed=True)
        data = parent_pubkey + index.to_bytes(4, "big")

    I = hmac.new(parent_chaincode, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    Il_int = int.from_bytes(IL, "big")
    kpar_int = int.from_bytes(parent_privkey, "big")
    n = SECP256k1.order

    child_priv_int = (Il_int + kpar_int) % n
    child_privkey = child_priv_int.to_bytes(32, "big")

    child_chaincode = IR
    return child_privkey, child_chaincode