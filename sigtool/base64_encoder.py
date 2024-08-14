# -*- coding: utf-8 -*-

import base64

class Base64Encoder:
    def __init__(self, signature_hex, hashes=None):
        self.signature_hex = signature_hex
        self.signature_bytes = bytes.fromhex(signature_hex)
        self.hashes = hashes

    def encode_signature(self):
        encoded_signature = base64.b64encode(self.signature_bytes).decode('utf-8')
        return encoded_signature

    def encode_hashes(self):
        if self.hashes is None:
            raise ValueError("Hashes are not provided.")
        encoded_hashes = {
            hash_type: base64.b64encode(bytes.fromhex(hash_value)).decode('utf-8')
            for hash_type, hash_value in self.hashes.items()
        }
        return encoded_hashes