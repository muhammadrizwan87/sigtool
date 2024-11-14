import argparse
import pkg_resources
import sys
import os
import re
import json

from .apk_info_extractor import APKInfoExtractor
from .apk_signature_extractor import APKSignatureExtractor
from .signature_hash_calculator import SignatureHashCalculator
from .crc32_and_hashcode_calculator import CRC32AndHashCodeCalculator
from .smali_bytearray_generator import SmaliByteArrayGenerator
from .base64_encoder import Base64Encoder
from .pem_certificate_generator import PEMCertificateGenerator
from .colon_uppercase import ColonUpperCase
from .output_formatter import OutputFormatter
from .pem_signature_extractor import PEMSignatureExtractor
from .sighooks.mt_enhanced_hook.mthook_generator import MTHookGenerator

class SigTool:
    def __init__(self, apk_path, args):
        self.apk_path = apk_path
        self.args = args
        self.extractor = APKInfoExtractor(apk_path)
        self.formatter = OutputFormatter()
        self.signature_hex = None
        self.hashes = None
        self.colon_upper = ColonUpperCase(
            apply_colons='-c' in args or '-uc' in args or '-fc' in args or '-fuc' in args,
            convert_uppercase='-u' in args or '-uc' in args or '-fu' in args or '-fuc' in args
        )
        self.results = {}

    def check_file_type(self):
        try:
            with open(self.apk_path, 'rb') as file:
                content = file.read(1024)
                
                if b'-----BEGIN CERTIFICATE-----' in content:
                    return 'pem'
                elif content.startswith(b'0\x82'):
                    return 'rsa'
                elif content.startswith(b'\x50\x4B\x03\x04'):
                    return 'apk'
                else:
                    print(self.formatter.format_error(f"Error: The APK, RSA or PEM file at '{self.apk_path}' does not exist or is not accessible."))
                    sys.exit(1)
        except Exception as e:
            print(self.formatter.format_error(f"Error: {e}"))
            sys.exit(1)

    def extract_apk_info(self):
        try:
            apk_info = self.extractor.get_apk_info()
            return {
                'App Name': apk_info.get('app_name', 'N/A'),
                'Package Name': apk_info.get('package_name', 'N/A'),
                'Version': apk_info.get('version_name', 'N/A'),
                'Build': apk_info.get('version_code', 'N/A')
            }
        except Exception as e:
            return {'Error': self.formatter.format_error(f"Failed to extract APK info: {e}")}

    def extract_signature_hex(self):
        try:
            file_type = self.check_file_type()
            if file_type == 'pem':
                extractor = PEMSignatureExtractor(pem_path=self.apk_path)
            elif file_type == 'rsa':
                rsa_extractor = PEMSignatureExtractor()
                pem_data = rsa_extractor.convert_rsa_to_pem(self.apk_path)
                extractor = PEMSignatureExtractor(pem_data=pem_data)
            else:
                extractor = APKSignatureExtractor(self.apk_path)
    
            self.signature_hex = extractor.extract_signatures()
            if self.signature_hex:
                self.signature_hex = self.colon_upper.convert_to_uppercase(self.signature_hex)
        except Exception as e:
            print(self.formatter.format_error(f"Error: {e}"))
            sys.exit(1)

    def calculate_hashes(self):
        return SignatureHashCalculator(self.signature_hex).calculate_hashes()

    def encode_base64(self, hashes):
        encoder = Base64Encoder(self.signature_hex, hashes)
        return encoder.encode_signature(), encoder.encode_hashes()

    def format_encoded_signature(self, encoded_signature):
        return re.sub(r'((.){1,76})', r'\1\\n', encoded_signature)

    def save_to_file(self, content, output_path):
        try:
            if not os.path.isabs(output_path):
                output_path = os.path.abspath(output_path)

            with open(output_path, 'w') as file:
                file.write(content)

            success_message = f"Output saved to {output_path}"
            print('\n', self.formatter.format_with_style(success_message, 'key'))
        except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as e:
            print(self.formatter.format_error(f"Error: {e}"))
            sys.exit(1)

    def add_section(self, section_name, section_content):
        self.results[section_name] = section_content

    def print_apk_info(self):
        if not os.path.isfile(self.apk_path):
            print(self.formatter.format_error(f"Error: The APK file at '{self.apk_path}' does not exist or is not accessible."))
            sys.exit(1)

        apk_info = self.extract_apk_info()
        if 'Error' in apk_info:
            print(self.formatter.format_error(f"Error: {apk_info['Error']}"))
            sys.exit(1)

        section_header = self.formatter.format_header("APK Information").lstrip("\n")
        result_lines = [self.formatter.format_result(k, v) for k, v in apk_info.items()]
        results_content = "\n".join(result_lines)
        output = f"\n{section_header}\n{self.formatter.format_divider()}\n{results_content}\n{self.formatter.format_divider()}"

        return output

    def print_default_results(self):
        self.extract_signature_hex()

        if self.signature_hex is None:
            print(self.formatter.format_error("Error: Failed to extract signature hex from the APK file."))
            sys.exit(1)

        hashes = self.calculate_hashes()
        crc32_hashcode = CRC32AndHashCodeCalculator(self.signature_hex).calculate_crc32_and_hash_code()

        formatted_hashes = self.colon_upper.process_signature_hashes(hashes)
        formatted_results = self.colon_upper.process_crc32_and_hashcode(crc32_hashcode)

        output = self.formatter.format_section("Calculated Hashes", formatted_hashes)
        output += self.formatter.format_section("CRC32 and hashCode Results", formatted_results)
        output += self.formatter.format_header("Certificate Bytes")
        output += self.formatter.format_result_two("toCharsString", self.signature_hex)

        self.add_section("Calculated Hashes", formatted_hashes)
        self.add_section("CRC32 and hashCode Results", formatted_results)
        self.add_section("Certificate Bytes", self.signature_hex)

        return output

    def print_encoded_results(self):
        encoded_signature, encoded_hashes = self.encode_base64(self.calculate_hashes())
        formatted_encoded_signature = self.format_encoded_signature(encoded_signature)

        output = self.formatter.format_section("Base64 Encoded Hashes", encoded_hashes)
        output += self.formatter.format_header("Base64 Encoded Certificate")
        output += self.formatter.format_result_two("Certificate", encoded_signature)
        output += self.formatter.format_result_two(
            "\nsignatures (Add '\\n' per 76 characters)", formatted_encoded_signature.lstrip("\n"))

        self.add_section("Base64 Encoded Hashes", encoded_hashes)
        self.add_section("Base64 Encoded Certificate", encoded_signature)
        self.add_section("signatures (Add '\n' per 76 characters)", formatted_encoded_signature.replace('\\n', '\n'))

        return output

    def print_pem_results(self):
        pem_certificate = PEMCertificateGenerator(self.signature_hex).generate_certificate_details()

        output = self.formatter.format_header("PEM Certificate Details\n")
        output += self.formatter.format_divider()
        output += self.formatter.format_value(f"\n{pem_certificate}")
        output += self.formatter.format_divider()

        self.add_section("PEM Certificate Details", pem_certificate)
        return output

    def print_smali_results(self):
        smali_representation = SmaliByteArrayGenerator(self.signature_hex).generate_smali()

        output = self.formatter.format_header("Byte Array Smali Format")
        output += self.formatter.format_result_two("toByteArray", smali_representation)

        self.add_section("Byte Array Smali Format", smali_representation)
        return output

    def generate_hook(self, encoded_cert, pkg_name, output_path):
        mthook_gen = MTHookGenerator(
            encoded_zip=None,
            apk_path=self.apk_path,
            pkg_name=pkg_name,
            encoded_cert=encoded_cert
        )
        mthook_gen.process(output_path)
    
    def run(self):
        try:
            output = ""
        
            file_type = self.check_file_type()
        
            if file_type == 'apk':
                output = self.print_apk_info()
        
            self.extract_signature_hex()
        
            if self.signature_hex is None:
                print(self.formatter.format_error("Error: Signature hex is None, cannot proceed."))
                sys.exit(1)
        
            encoded_signature, encoded_hashes = self.encode_base64(self.calculate_hashes())
    
            if '-hmt' in self.args and file_type == 'apk':
                apk_info = self.extract_apk_info()
                app_name = apk_info.get('App Name', 'N/A')
                pkg_name = apk_info.get('Package Name', 'N/A')
                version = apk_info.get('Version', 'N/A')
                build = apk_info.get('Build', 'N/A')
            
                output_filename = f"mthook_{app_name}_{version}({build}).zip"
                output_directory = self.args[self.args.index('-o') + 1] if '-o' in self.args else os.path.dirname(os.path.abspath(self.apk_path))
            
                if not os.path.isdir(output_directory):
                    print(self.formatter.format_error(f"Error: The specified path '{output_directory}' is not a valid directory."))
                    print(self.formatter.format_error(f"Please provide a valid directory where the {output_filename} file can be saved."))
                    sys.exit(1)
            
                output_path = os.path.join(output_directory, output_filename)
                formatted_signature = self.format_encoded_signature(encoded_signature)
                self.generate_hook(formatted_signature, pkg_name, output_path)
            
                print(self.formatter.format_with_style(f"\nHook exported to {output_path}", 'key'))
                sys.exit(0)
                
            if '-f' in self.args or '-fc' in self.args or '-fu' in self.args or '-fuc' in self.args:
                output += self.print_default_results()
                output += self.print_encoded_results()
                output += self.print_pem_results()
                output += self.print_smali_results()
            elif '-e' in self.args:
                output += self.print_encoded_results()
            elif '-p' in self.args:
                output += self.print_pem_results()
            elif '-a' in self.args:
                output += self.print_smali_results()
            else:
                output += self.print_default_results()
        
            if '-o' in self.args:
                output_path = self.args[self.args.index('-o') + 1]
        
                if not output_path.endswith('.json'):
                    logo_two = self.formatter.display_logo_two()
                    output = self.formatter.remove_ansi(output)
                    output = logo_two + output
                    self.save_to_file(output, output_path)
                else:
                    final_results = {"Meta Data": self.formatter.meta_data}
                    final_results.update(self.results)
                    json_output = json.dumps(final_results, indent=4)
                    self.save_to_file(json_output, output_path)
            else:
                logo_one = self.formatter.display_logo_one()
                output = logo_one + output
                print(output)
        except ValueError as ve:
            print(self.formatter.format_error(f"ValueError: {ve}"))
            sys.exit(1)
        except Exception as e:
            print(self.formatter.format_error(f"Error: {e}"))
            sys.exit(1)
    
def get_version():
    try:
        return pkg_resources.get_distribution("sigtool").version
    except pkg_resources.DistributionNotFound:
        return "Unknown version"


def main():
    usage_msg = "sigtool <apk_path> [-a] [-c] [-e] [-f] [-fc] [-fu] [-fuc] [-p] [-u] [-uc] [-hmt] [-o <output_path>]"
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

  To save results in JSON format:
  sigtool /path/to/apk -f -o /path/to/output.json

  To export hook of MT enhanced version:
  sigtool /path/to/apk -hmt -o /path/to/hook
"""

    version = get_version()
    parser = argparse.ArgumentParser(
        description=(
            "SigTool is a powerful tool designed by MuhammadRizwan from India, "
            "for in-depth APK signature and keystore analysis.\n"
            "It retrieves detailed certificate information, calculates key hashes (such as CRC32 and java style hashCode), "
            "and includes options for Base64 encoding, PEM parsing, and Smali-format byte array generation.\n"
            "SigTool can also generate an MT VIP hook to bypass APK signatures. "
            "With formatting options such as JSON output, uppercase, and colon-separated values.\n"
            "SigTool provides the flexibility you need in APK analysis. \n\n"
            "Github Repository: https://github.com/muhammadrizwan87/sigtool\n"
            "Telegram Channel: https://TDOhex.t.me\n"
            "Second Channel: https://Android_Patches.t.me\n"
            "Discussion Group: https://TDOhex_Discussion.t.me"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=usage_msg,
        epilog=example_usage
    )
    
    parser.add_argument('apk_path', type=str, help="Path to the APK file")
    parser.add_argument('-u', action='store_true', help="Convert output to uppercase")
    parser.add_argument('-c', action='store_true', help="Add colons to certificate hashes")
    parser.add_argument('-uc', action='store_true', help="Add colons to hashes and convert output to uppercase")
    parser.add_argument('-e', action='store_true', help="Encode output in Base64")
    parser.add_argument('-p', action='store_true', help="Parse PEM Certificate")
    parser.add_argument('-a', action='store_true', help="Generate Smali Byte Array")
    parser.add_argument('-f', action='store_true', help="Print All Information")
    parser.add_argument('-fc', action='store_true', help="Add colons to hashes and print all information")
    parser.add_argument('-fu', action='store_true', help="Convert output to uppercase and print all information")
    parser.add_argument('-fuc', action='store_true', help="Add colons to hashes, convert output to uppercase and print all information")
    parser.add_argument('-hmt', action='store_true', help="Generate and export hook of MT enhanced version")
    parser.add_argument('-o', type=str, help="Output results to a specified file path. If the path ends with '.json', results will be saved in JSON format.")
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {version}', help="Show program's version number and exit")

    args = parser.parse_args()

    if len(sys.argv) < 2 or len(sys.argv) > 6:
        parser.print_help()
        sys.exit(1)

    valid_args = {'-u', '-c', '-uc', '-e', '-p', '-a', '-f', '-fc', '-fu', '-fuc', '-hmt', '-o'}

    if len(sys.argv) > 2:
        if sys.argv[2] not in valid_args:
            parser.print_help()
            sys.exit(1)

        if sys.argv[2] == '-o':
            if len(sys.argv) != 4:
                parser.print_help()
                sys.exit(1)
        else:
            if len(sys.argv) > 3 and sys.argv[3] != '-o':
                parser.print_help()
                sys.exit(1)
            if len(sys.argv) == 5 and sys.argv[3] == '-o' and not sys.argv[4]:
                parser.print_help()
                sys.exit(1)

    sig_tool = SigTool(args.apk_path, sys.argv[1:])
    sig_tool.run()


if __name__ == '__main__':
    main()