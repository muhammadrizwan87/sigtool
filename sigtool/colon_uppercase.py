# -*- coding: utf-8 -*-

class ColonUpperCase:
    def __init__(self, apply_colons=False, convert_uppercase=False):
        self.apply_colons = apply_colons
        self.convert_uppercase = convert_uppercase

    def add_colons_to_hex(self, hex_string: str) -> str:
        if self.apply_colons:
            return ':'.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))
        return hex_string

    def convert_to_uppercase(self, string: str) -> str:
        if self.convert_uppercase:
            return string.upper()
        return string.lower()

    def convert_crc32_and_hashcode(self, value: str) -> str:
        if value.startswith('0x'):
            return '0x' + self.convert_to_uppercase(value[2:])
        return self.convert_to_uppercase(value)

    def process_signature_hashes(self, hashes: dict) -> dict:
        processed_hashes = {}
        for hash_type, hex_value in hashes.items():
            hex_value = self.convert_to_uppercase(hex_value)
            processed_hashes[hash_type] = self.add_colons_to_hex(hex_value)
        return processed_hashes

    def process_crc32_and_hashcode(self, results: dict) -> dict:
        processed_results = {}
        for key, value in results.items():
            if isinstance(value, str):
                processed_results[key] = self.convert_crc32_and_hashcode(value)
            else:
                processed_results[key] = value
        return processed_results