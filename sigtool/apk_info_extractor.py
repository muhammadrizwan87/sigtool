# -*- coding: utf-8 -*-

import subprocess

class APKInfoExtractor:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def get_apk_info(self) -> dict:
        result = subprocess.run(
            ["aapt", "dump", "badging", self.apk_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            raise RuntimeError(f"aapt error: {result.stderr.decode()}")

        output = result.stdout.decode()
        app_info = {}
        for line in output.split('\n'):
            if line.startswith('package:'):
                package_info = line.split()
                for info in package_info:
                    if info.startswith('name='):
                        app_info['package_name'] = info.split('=')[1].strip("'")
                    elif info.startswith('versionCode='):
                        app_info['version_code'] = info.split('=')[1].strip("'")
                    elif info.startswith('versionName='):
                        app_info['version_name'] = info.split('=')[1].strip("'")
            elif line.startswith('application:'):
                app_info['app_name'] = line.split("label='")[1].split("'")[0]
        return app_info
