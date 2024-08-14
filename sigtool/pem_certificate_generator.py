# -*- coding: utf-8 -*-

import base64
import subprocess

class PEMCertificateGenerator:
    def __init__(self, signature_hex):
        self.signature_hex = signature_hex
        self.signature_bytes = bytes.fromhex(signature_hex)

    def _create_pem_certificate(self):
        if not self.signature_hex:
            raise ValueError("Signature hex is required to create the PEM certificate.")
        signature_bytes = bytes.fromhex(self.signature_hex)
        encoded_signature = base64.b64encode(signature_bytes).decode('utf-8')
        pem_certificate = "-----BEGIN CERTIFICATE-----\n"
        pem_certificate += encoded_signature
        pem_certificate += "\n-----END CERTIFICATE-----"
        return pem_certificate

    def _get_certificate_details(self, pem_certificate):
        result = subprocess.run(
            ['openssl', 'x509', '-text', '-noout'],
            input=pem_certificate,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Error: {result.stderr}")
        return result.stdout

    def generate_certificate_details(self):
        try:
            pem_certificate = self._create_pem_certificate()
            return self._get_certificate_details(pem_certificate)
        except Exception as e:
            return f"\033[91mError: {str(e)}\033[0m\n"