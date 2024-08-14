# -*- coding: utf-8 -*-

class ColonUpperCase:
    def __init__(self):
        pass

    def add_colons_to_hex(self, hex_string: str) -> str:
        return ':'.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))

    def convert_to_uppercase(self, string: str) -> str:
        return string.upper()

    def process_signature_hashes(self, hashes: dict) -> dict:
        processed_hashes = {}
        for hash_type, hex_value in hashes.items():
            upper_hex_value = self.convert_to_uppercase(hex_value)
            processed_hashes[hash_type] = self.add_colons_to_hex(upper_hex_value)
        return processed_hashes

    def process_crc32_and_hashcode(self, results: dict) -> dict:
        processed_results = {}
        for key, value in results.items():
            if isinstance(value, str):
                processed_results[key] = self.convert_to_uppercase(value)
            else:
                processed_results[key] = value
        return processed_results