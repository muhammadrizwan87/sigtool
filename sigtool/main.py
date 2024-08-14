#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import re
import importlib.metadata

from .apk_info_extractor import APKInfoExtractor
from .apk_signature_extractor import APKSignatureExtractor
from .signature_hash_calculator import SignatureHashCalculator
from .crc32_and_hashcode_calculator import CRC32AndHashCodeCalculator
from .smali_bytearray_generator import SmaliByteArrayGenerator
from .base64_encoder import Base64Encoder
from .pem_certificate_generator import PEMCertificateGenerator
from .colon_uppercase import ColonUpperCase
from .output_formatter import OutputFormatter

class SigTool:
    def __init__(self, apk_path, args):
        self.apk_path = apk_path
        self.args = args
        self.extractor = APKInfoExtractor(apk_path)
        self.formatter = OutputFormatter()
        self.colon_upper = ColonUpperCase()
        self.signature_hex = None
        self.hashes = None

    def extract_apk_info(self):
        try:
            apk_info = self.extractor.get_apk_info()
            formatted_apk_info = {
                'App Name': apk_info.get('app_name', 'N/A'),
                'Package Name': apk_info.get('package_name', 'N/A'),
                'Version': apk_info.get('version_name', 'N/A'),
                'Build': apk_info.get('version_code', 'N/A')
            }
            return formatted_apk_info
        except Exception as e:
            error_message = f"Failed to extract APK info: {e}"
            return {'Error': self.formatter.format_error(error_message)}

    def extract_signature_hex(self):
        try:
            extractor = APKSignatureExtractor(self.apk_path)
            self.signature_hex = extractor.extract_signatures()
        except Exception as e:
            print(self.formatter.format_error(f"Error: {e}"))
            return None

    def calculate_hashes(self):
        hash_calculator = SignatureHashCalculator(self.signature_hex)
        hashes = hash_calculator.calculate_hashes()
        return hashes

    def calculate_crc32_and_hashcode(self):
        crc32_calculator = CRC32AndHashCodeCalculator(self.signature_hex)
        results = crc32_calculator.calculate_crc32_and_hash_code()
        return results

    def generate_smali(self):
        smali_generator = SmaliByteArrayGenerator(self.signature_hex)
        smali_representation = smali_generator.generate_smali()
        return smali_representation

    def encode_base64(self, hashes):
        encoder = Base64Encoder(self.signature_hex, hashes)
        encoded_signature = encoder.encode_signature()
        encoded_hashes = encoder.encode_hashes()
        return encoded_signature, encoded_hashes

    def format_encoded_signature(self, encoded_signature):
        return re.sub(r'((.){1,76})', r'\1\\n', encoded_signature)
    
    def generate_pem_certificate(self):
        pem_generator = PEMCertificateGenerator(self.signature_hex)
        certificate_details = pem_generator.generate_certificate_details()
        return certificate_details

    def apply_colon_uppercase(self, hashes, crc32_hashcode):
        formatted_hashes = self.colon_upper.process_signature_hashes(hashes)
        formatted_results = self.colon_upper.process_crc32_and_hashcode(crc32_hashcode)
        return formatted_hashes, formatted_results

    def save_to_file(self, content, output_path):
        try:
            if not os.path.isabs(output_path):
                output_path = os.path.abspath(output_path)
            
            with open(output_path, 'w') as file:
                file.write(content)
            
            success_message = f"Output saved to {output_path}"
            print('\n', self.formatter.format_with_style(success_message, 'key'))
        
        except FileNotFoundError:
            print(self.formatter.format_error(f"Error: The directory for the specified output path '{output_path}' does not exist."))
            sys.exit(1)
        except PermissionError:
            print(self.formatter.format_error(f"Error: Permission denied when trying to write to '{output_path}'."))
            sys.exit(1)
        except Exception as e:
            print(self.formatter.format_error(f"Unexpected error: {e}"))
            sys.exit(1)

    def run(self):
        if not os.path.isfile(self.apk_path):
            print(self.formatter.format_error(f"Error: The APK file at '{self.apk_path}' does not exist or is not accessible."))
            sys.exit(1)
    
        apk_info = self.extract_apk_info()
        if 'Error' in apk_info:
            print(self.formatter.format_error(f"Error: {apk_info['Error']}"))
            sys.exit(1)
    
        logo_one = self.formatter.display_logo_one()
        logo_two = self.formatter.display_logo_two()
        section_header = self.formatter.format_header("APK Information").lstrip("\n")
        result_lines = [self.formatter.format_result(k, v) for k, v in apk_info.items()]
        results_content = "\n".join(result_lines)
        output = f"\n{section_header}\n{self.formatter.format_divider()}\n{results_content}\n{self.formatter.format_divider()}"
        self.extract_signature_hex()
        
        if self.signature_hex is None:
            print(self.formatter.format_error("Error: Failed to extract signature hex from the APK file."))
            sys.exit(1)
    
        hashes = self.calculate_hashes()
        crc32_hashcode = self.calculate_crc32_and_hashcode()
    
        if '-u' in self.args:
            self.signature_hex = self.colon_upper.convert_to_uppercase(self.signature_hex)
            hashes = {k: self.colon_upper.convert_to_uppercase(v) for k, v in hashes.items()}
            crc32_hashcode = self.colon_upper.process_crc32_and_hashcode(crc32_hashcode)

        if '-c' in self.args:
            hashes = self.colon_upper.process_signature_hashes(hashes)

        if '-e' in self.args:
            encoded_signature, encoded_hashes = self.encode_base64(hashes)
            formatted_encoded_signature = self.format_encoded_signature(encoded_signature)
            output += self.formatter.format_section("Base64 Encoded Hashes", encoded_hashes)
            output += self.formatter.format_header("Base64 Encoded Certificate")
            output += self.formatter.format_result_two("Certificate", encoded_signature)
            output += self.formatter.format_result_two("\nsignatures (Add '\\n' per 76 characters)", f"{formatted_encoded_signature}".lstrip("\n"))

        elif '-p' in self.args:
            pem_certificate = self.generate_pem_certificate()
            output += self.formatter.format_header("PEM Certificate Details\n")
            output += self.formatter.format_divider()
            output += self.formatter.format_value(f"\n{pem_certificate}")
            output += self.formatter.format_divider()

        elif '-a' in self.args:
            smali_representation = self.generate_smali()
            output += self.formatter.format_header("Byte Array Smali Format")
            output += self.formatter.format_result_two("toByteArray", smali_representation)

        elif '-f' in self.args:
            output += self.formatter.format_section("Calculated Hashes", hashes)
            output += self.formatter.format_section("CRC32 and hashCode Results", crc32_hashcode)
            output += self.formatter.format_header("Certificate Bytes")
            output += self.formatter.format_result_two("toCharsString", self.signature_hex)
            encoded_signature, encoded_hashes = self.encode_base64(hashes)
            formatted_encoded_signature = self.format_encoded_signature(encoded_signature)
            output += self.formatter.format_section("Base64 Encoded Hashes", encoded_hashes)
            output += self.formatter.format_header("Base64 Encoded Certificate")
            output += self.formatter.format_result_two("Certificate", encoded_signature)
            output += self.formatter.format_result_two("\nsignatures (Add '\\n' per 76 characters)", f"{formatted_encoded_signature}".lstrip("\n"))
            pem_certificate = self.generate_pem_certificate()
            output += self.formatter.format_header("PEM Certificate Details\n")
            output += self.formatter.format_divider()
            output += self.formatter.format_value(f"\n{pem_certificate}")
            output += self.formatter.format_divider()
            smali_representation = self.generate_smali()
            output += self.formatter.format_header("Byte Array Smali Format")
            output += self.formatter.format_result_two("toByteArray", smali_representation)
        
        else:
            output += self.formatter.format_section("Calculated Hashes", hashes)
            output += self.formatter.format_section("CRC32 and hashCode Results", crc32_hashcode)
            output += self.formatter.format_header("Certificate Bytes")
            output += self.formatter.format_result_two("toCharsString", self.signature_hex)
        
        if '-o' in self.args:
            output = logo_two + output
            output = self.formatter.remove_ansi(output)
            if len(self.args) > self.args.index('-o') + 1:
                output_path = self.args[self.args.index('-o') + 1]
            else:
                print(self.formatter.format_error("Error: '-o' requires a valid output path."))
                sys.exit(1)
            self.save_to_file(output, output_path)
        else:
            output = logo_one + output
            print(output)

def main():
    usage_msg = "sigtool <apk_path> [-a] [-c] [-e] [-f] [-p] [-u] [-o <output_path>]"
    example_usage = """
Examples:
    To print the default results:
    sigtool /path/to/apk
    
    To save the default results to a file:
    sigtool /path/to/apk -o /path/to/output.txt
    
    To print the Base64-encoded results:
    sigtool /path/to/apk -e
    
    To save all results to a file:
    sigtool /path/to/apk -f -o /path/to/output.bin
"""

    try:
        version = importlib.metadata.version('sigtool')
    except importlib.metadata.PackageNotFoundError:
        version = "v1.0"

    parser = argparse.ArgumentParser(
        description="SigTool is a powerful tool designed by MuhammadRizwan from India for in-depth analysis of APK files by retrieving detailed certificate information. It calculates various hash values, including CRC32 and hashCode. The tool also offers options for base64 encoding, PEM certificate parsing, and generating byte arrays in Smali format. Additionally, it supports handling output files and formatting options such as uppercase and colon-separated formats. \n\nGithub Repository: https://github.com/muhammadrizwan87\nTelegram Channel: https://TDOhex.t.me\nSecond Channel: https://Android_Patches.t.me\nDiscussion Group: https://TDOhex_Discussion.t.me",
        formatter_class=argparse.RawTextHelpFormatter,
        usage=usage_msg,
        epilog=example_usage
    )
    parser.add_argument('apk_path', type=str, help="Path to the APK file")
    parser.add_argument('-u', action='store_true', help="Convert output to uppercase")
    parser.add_argument('-c', action='store_true', help="Add colons to certificate hashes")
    parser.add_argument('-e', action='store_true', help="Encode output in Base64")
    parser.add_argument('-p', action='store_true', help="Parse PEM Certificate")
    parser.add_argument('-a', action='store_true', help="Generate Smali Byte Array")
    parser.add_argument('-f', action='store_true', help="Print All Information")
    parser.add_argument('-o', type=str, help="Output results to a specified file path")
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {version}', help="Show program's version number and exit")

    args = parser.parse_args()

    if len(sys.argv) < 2 or len(sys.argv) > 5:
        parser.print_help()
        sys.exit(1)

    if sys.argv[1].startswith('-'):
        parser.print_help()
        sys.exit(1)

    valid_args = {'-u', '-c', '-e', '-p', '-a', '-f', '-o'}

    if len(sys.argv) > 2 and sys.argv[2] not in valid_args:
        parser.print_help()
        sys.exit(1)

    if len(sys.argv) > 3:
        if sys.argv[3] == '-o' and len(sys.argv) == 5:
            output_path = sys.argv[4]
        elif sys.argv[3] == '-o':
            parser.print_help()
            sys.exit(1)
        else:
            output_path = sys.argv[3]

    sig_tool = SigTool(args.apk_path, sys.argv[1:])
    sig_tool.run()

if __name__ == '__main__':
    main()