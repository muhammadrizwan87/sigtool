# -*- coding: utf-8 -*-

import hashlib

class SignatureHashCalculator:
    def __init__(self, signature_hex):
        self.signature_hex = signature_hex
        self.signature_bytes = bytes.fromhex(signature_hex)

    def _calculate_sha1(self):
        sha1 = hashlib.sha1(self.signature_bytes)
        return sha1.hexdigest()

    def _calculate_sha256(self):
        sha256 = hashlib.sha256(self.signature_bytes)
        return sha256.hexdigest()

    def _calculate_md5(self):
        md5 = hashlib.md5(self.signature_bytes)
        return md5.hexdigest()

    def _calculate_sha224(self):
        sha224 = hashlib.sha224(self.signature_bytes)
        return sha224.hexdigest()

    def _calculate_sha384(self):
        sha384 = hashlib.sha384(self.signature_bytes)
        return sha384.hexdigest()

    def _calculate_sha512(self):
        sha512 = hashlib.sha512(self.signature_bytes)
        return sha512.hexdigest()

    def calculate_hashes(self):
        return {
            "SHA-1": self._calculate_sha1(),
            "SHA-256": self._calculate_sha256(),
            "MD5": self._calculate_md5(),
            "SHA-224": self._calculate_sha224(),
            "SHA-384": self._calculate_sha384(),
            "SHA-512": self._calculate_sha512()
        }