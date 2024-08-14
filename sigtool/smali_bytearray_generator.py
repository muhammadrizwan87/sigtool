# -*- coding: utf-8 -*-

from typing import List

class SmaliByteArrayGenerator:
    def __init__(self, signature_hex):
        self.signature_hex = signature_hex

    def convert_hex_to_array(self, hex_string: str) -> List[int]:
        byte_array = bytes.fromhex(hex_string)
        return [byte - 256 if byte > 127 else byte for byte in byte_array]

    def format_array_data(self, array_data: List[int]) -> str:
        formatted_lines = [
            "    nop",
            "    label_0:",
            "    .array_data"
        ]
        formatted_lines.extend(
            f"        {'0x' if value >= 0 else '-0x'}{abs(value):02x}t" for value in array_data
        )
        formatted_lines.extend([
            "    .end array_data",
            f"    length:0x{len(array_data) * 2:03x}"
        ])
        return "\n".join(formatted_lines)

    def generate_smali(self) -> str:
        array_data = self.convert_hex_to_array(self.signature_hex)
        return self.format_array_data(array_data)