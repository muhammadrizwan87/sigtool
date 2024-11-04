# -*- coding: utf-8 -*-

import base64
import subprocess

class PEMSignatureExtractor:
    def __init__(self, pem_path=None, pem_data=None):
        self.pem_path = pem_path
        self.pem_data = pem_data
        self.signature_hex = None

    def _extract_base64_cert(self):
        pem_data = self.pem_data
        if self.pem_path:
            with open(self.pem_path, 'r') as pem_file:
                pem_data = pem_file.read()

        start_marker = "-----BEGIN CERTIFICATE-----"
        end_marker = "-----END CERTIFICATE-----"

        start_index = pem_data.find(start_marker)
        end_index = pem_data.find(end_marker)

        if start_index == -1 or end_index == -1:
            raise ValueError("Invalid PEM file: Certificate markers not found")

        base64_cert = pem_data[start_index + len(start_marker):end_index].strip()
        return base64_cert

    def extract_signatures(self):
        try:
            base64_cert = self._extract_base64_cert()
            decoded_bytes = base64.b64decode(base64_cert)
            self.signature_hex = decoded_bytes.hex()
            return self.signature_hex
        except Exception as e:
            raise ValueError(f"Failed to extract signature from PEM data: {e}")

    def convert_rsa_to_pem(self, rsa_path):
        try:
            result = subprocess.run(
                ['openssl', 'pkcs7', '-inform', 'DER', '-print_certs', '-in', rsa_path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                raise ValueError(f"Failed to convert RSA to PEM: {result.stderr.decode('utf-8')}")
            
            pem_data = result.stdout.decode('utf-8')
            return pem_data
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Error during RSA to PEM conversion: {e.stderr.decode('utf-8')}")