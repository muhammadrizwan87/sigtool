# -*- coding: utf-8 -*-

import struct

class APKSignatureExtractor:
    def __init__(self, apk_path):
        self.apk_path = apk_path

    def _read_bytes(self, file, offset, length):
        file.seek(offset)
        return file.read(length)

    def _find_eocd(self, file):
        file.seek(-65536, 2)
        data = file.read(65536)
        eocd_offset = data.rfind(b'PK\x05\x06')
        if eocd_offset == -1:
            raise ValueError("Invalid APK: End of Central Directory signature not found")
        eocd = data[eocd_offset:eocd_offset + 22]
        return struct.unpack('<I', eocd[16:20])[0]

    def _find_apk_signing_block(self, file, cd_offset):
        file.seek(cd_offset - 24)
        block_size = struct.unpack('<Q', file.read(8))[0]
        magic = file.read(16)
        if magic != b'APK Sig Block 42':
            raise ValueError("Invalid APK: APK Signing Block not found")
        return block_size

    def _extract_first_signature(self, signing_block):
        index = 0
        while index < len(signing_block):
            index = signing_block.find(b'\x30\x82', index)
            if index == -1:
                return None
            length = struct.unpack_from('>H', signing_block, index + 2)[0]
            sig_length = 4 + length
            if index + sig_length <= len(signing_block):
                return signing_block[index:index + sig_length]
            index += sig_length
        return None

    def extract_signatures(self):
        try:
            with open(self.apk_path, 'rb') as file:
                cd_offset = self._find_eocd(file)
                block_size = self._find_apk_signing_block(file, cd_offset)
                file.seek(cd_offset - block_size)
                signing_block = file.read(block_size)
                signature = self._extract_first_signature(signing_block)
                if signature:
                    return signature.hex()
                else:
                    return "No signature found in APK Signing Block"
        except FileNotFoundError:
            return "Error: APK file not found"
        except ValueError as ve:
            return f"Error: {str(ve)}"
        except Exception as e:
            return f"Unexpected error: {str(e)}"