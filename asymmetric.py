
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

DHLen = 32
# A constant specifying the size in bytes of public keys and DH outputs.
# For security reasons, dhLen must be 32 or greater.


class KeyPair(object):
    def __init__(self, key_pair):
        self.private_key = key_pair.private_key
        self.public_key = key_pair.public_key


def generate_key_pair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    key_pair = KeyPair(private_key, public_key)
    return key_pair


def dh(key_pair, public_key):
    shared_key = key_pair.private_key.exchange(public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    return derived_key
