# -*- coding: utf-8 -*-

import base64
import io
import zipfile
import re
import os
import subprocess
import tempfile
from typing import List, Dict

from .mthook import get_encoded_zip


class MTHookGenerator:
    def __init__(self, encoded_zip: str, apk_path: str, pkg_name: str, encoded_cert: str):
        self.encoded_zip = get_encoded_zip()
        self.apk_path = apk_path
        self.pkg_name = pkg_name
        self.encoded_cert = encoded_cert
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        self.root_dir = os.path.dirname(os.path.dirname(current_file_dir))
        self.lib_path = os.path.join(self.root_dir, 'lib')
        self.smali_jar_path = os.path.join(self.lib_path, 'smali.jar')

    def decode_base64(self) -> bytes:
        return base64.b64decode(self.encoded_zip)

    def extract_zip(self, zip_data: bytes) -> Dict[str, bytes]:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            return {name: z.read(name) for name in z.namelist()}

    def modify_smali_file(self, smali_data: bytes) -> bytes:
        content = smali_data.decode('utf-8')
        content = content.replace('pkg_name', self.pkg_name)
        formatted_encoded_cert = self.encoded_cert.replace('\n', '\\n')

        def replace_encoded_cert(match):
            return formatted_encoded_cert

        content = re.sub(r'encoded_certificate_bytes', replace_encoded_cert, content)
        return content.encode('utf-8')

    def manage_lib_folders(self, apk_libs: List[str], zip_libs: List[str]) -> List[str]:
        if not apk_libs:
            return zip_libs
        return [lib for lib in zip_libs if lib in apk_libs]

    def get_apk_architectures(self) -> List[str]:
        with zipfile.ZipFile(self.apk_path) as apk_zip:
            apk_lib_folders = [name for name in apk_zip.namelist() if name.startswith('lib/') and len(name.split('/')) == 3]
            return list(set(name.split('/')[1] for name in apk_lib_folders))

    def count_dex_files(self) -> int:
        with zipfile.ZipFile(self.apk_path) as apk_zip:
            dex_files = [name for name in apk_zip.namelist() if name.endswith('.dex') and '/' not in name]
            return len(dex_files)

    def save_smali_files(self, files: Dict[str, bytes], temp_dir: str) -> None:
        for name, data in files.items():
            file_path = os.path.join(temp_dir, name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(data)

    def convert_smali_to_dex(self, smali_dir: str, output_dex_path: str) -> None:
        smali_command = ['java', '-jar', self.smali_jar_path, 'assemble', smali_dir, '-o', output_dex_path]
        subprocess.run(smali_command, check=True)

    def handle_hook_modification(self, files: Dict[str, bytes], temp_dir: str) -> None:
        for name, data in files.items():
            if name == 'classes.zip':
                with zipfile.ZipFile(io.BytesIO(data)) as hook_zip:
                    for hook_name in hook_zip.namelist():
                        hook_data = hook_zip.read(hook_name)
                        if hook_name == 'android/app/application.smali':
                            hook_data = self.modify_smali_file(hook_data)
                        file_path = os.path.join(temp_dir, hook_name)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        with open(file_path, 'wb') as f:
                            f.write(hook_data)

    def add_lib_files(self, new_zip: zipfile.ZipFile, files: Dict[str, bytes], valid_libs: List[str]) -> None:
        zip_lib_folder = 'lib'
        for name, data in files.items():
            if name.startswith(f'{zip_lib_folder}/'):
                arch = name.split('/')[1]
                if not valid_libs or arch in valid_libs:
                    new_zip.writestr(name, data)

    def add_assets_folder(self, new_zip: zipfile.ZipFile, files: Dict[str, bytes]) -> None:
        for name, data in files.items():
            if name == 'assets/fonts/droidsans.ttf':
                with open(self.apk_path, 'rb') as apk_file:
                    new_zip.writestr('assets/fonts/droidsans.ttf', apk_file.read())
            elif name.startswith('assets/'):
                new_zip.writestr(name, data)

    def add_dex_file(self, new_zip: zipfile.ZipFile, dex_output_path: str, new_dex_name: str) -> None:
        with open(dex_output_path, 'rb') as dex_file:
            new_zip.writestr(new_dex_name, dex_file.read())

    def prepare_new_zip(self, files: Dict[str, bytes], dex_output_path: str, valid_libs: List[str], new_dex_name: str) -> bytes:
        new_zip_buffer = io.BytesIO()
        with zipfile.ZipFile(new_zip_buffer, 'w') as new_zip:
            self.add_lib_files(new_zip, files, valid_libs)
            self.add_assets_folder(new_zip, files)
            self.add_dex_file(new_zip, dex_output_path, new_dex_name)
        return new_zip_buffer.getvalue()

    def modify_zip(self, zip_data: bytes) -> bytes:
        files = self.extract_zip(zip_data)

        dex_count = self.count_dex_files()
        new_dex_name = f'classes{dex_count + 1}.dex'

        apk_libs = self.get_apk_architectures()
        original_libs = [name for name in files if name.startswith('lib/')]
        lib_architectures = list(set(name.split('/')[1] for name in original_libs))
        valid_libs = self.manage_lib_folders(apk_libs, lib_architectures)

        with tempfile.TemporaryDirectory() as temp_dir:
            self.handle_hook_modification(files, temp_dir)

            dex_output_path = os.path.join(temp_dir, new_dex_name)
            self.convert_smali_to_dex(temp_dir, dex_output_path)

            return self.prepare_new_zip(files, dex_output_path, valid_libs, new_dex_name)

    def process(self, output_path: str) -> None:
        decoded_zip = self.decode_base64()
        modified_zip = self.modify_zip(decoded_zip)
        self.save_modified_zip(output_path, modified_zip)

    def save_modified_zip(self, output_path: str, modified_zip: bytes) -> None:
        with open(output_path, 'wb') as f:
            f.write(modified_zip)