
from github_com.mimoo/strobe-mirror/tree/master/python import Strobe

#SymmetriccState
class SymmetricState:

    def __init__(self):
        self.strobeState = Strobe()
        self.isKeyed = False

    def initialize_symmetric(self, protocol_name):
        self.strobeState = Strobe(protocol_name)

    def mix_key(self, input_key_material):
        self.strobeState.ad(input_key_material)
        self.isKeyed = True

    def mix_hash(self, data):
        self.strobeState.ad(data)

    def mix_key_and_hash(self, input_key_material):
        self.strobeState.ad(input_key_material)

    def get_handshake_hash(self):
        self.strobeState.prf(32)

    def encrypt_and_hash(self, plaintext):
        if not self.isKeyed:
            self.strobeState.send_clr(plaintext)
            return plaintext
        else:
            enc = self.strobeState.send_enc(plaintext)
            mac = self.strobeState.send_mac(16)
            return enc + mac

    def decrypt_and_hash(self, ciphertext):
        if not self.isKeyed:
            self.strobeState.recv_clr(ciphertext)
            return ciphertext
        else:
            if len(ciphertext) < 16:
                return "disco: the received payload is shorter 16 bytes"
            plaintext = self.strobeState.recv_enc(ciphertext[:16])
            if not self.strobeState.recv_mac(ciphertext[16:]):
                return "disco: cannot decrypt the payload"
            else:
                return plaintext

    def split(self):
        s1 = self.strobeState
        s2 = self.strobeState.copy()
        s1.meta_ad("initiator")
        s2.meta_ad("responder")
        s1.ratchet(16)
        s2.ratchet(16)
        return s1, s2
