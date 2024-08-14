# -*- coding: utf-8 -*-

import zlib

class CRC32AndHashCodeCalculator:
    def __init__(self, signature_hex):
        self.signature_hex = signature_hex
        self.signature_bytes = bytes.fromhex(signature_hex)

    def _calculate_crc32(self):
        crc32 = zlib.crc32(self.signature_bytes)
        return crc32

    def _calculate_hash_code(self):
        hex_string = self.signature_hex
        length = len(hex_string)
        data = bytearray(length // 2)
        for i in range(0, length, 2):
            data[i // 2] = (int(hex_string[i], 16) << 4) + int(hex_string[i + 1], 16)
        byte_array = data
        result = 1
        for b in byte_array:
            b = b if b < 128 else b - 256
            result = (31 * result + b) & 0xFFFFFFFF
        if result >= 0x80000000:
            signed_result = result - 0x100000000
        else:
            signed_result = result
        unsigned_hex_result = hex(result)
        hashCode = f"{unsigned_hex_result} ({signed_result})"
        return hashCode

    def calculate_crc32_and_hash_code(self):
        crc32 = self._calculate_crc32()
        crc32 = f"0x{crc32:08x} ({crc32 - 0x100000000 if crc32 >= 0x80000000 else crc32})"
        
        hashCode = self._calculate_hash_code()

        return {
            "CRC32": crc32,
            "hashCode": hashCode,
        }