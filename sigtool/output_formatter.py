# -*- coding: utf-8 -*-

import re

class OutputFormatter:
    def __init__(self):
        self.styles = {
            "header": "\033[35m",      # Magenta
            "key": "\033[92m",         # Green
            "value": "\033[93m",       # Yellow/Gold
            "divider": "\033[94m",     # Blue
            "error": "\033[91m",       # Red
            "bold": "\033[1m",         # Bold
            "underline": "\033[4m",    # Underline
            "endc": "\033[0m"          # End coloring
        }
        self.logo_one = """\n+----------Welcome to-------------+
|                                 |
|  ____  _      _____           _ |
| / ___|(_) __ |_   _|__   ___ | ||
| \\___ \\| |/ _` || |/ _ \\ / _ \\| ||
|  ___) | | (_| || | (_) | (_) | ||
| |____/|_|\\__, ||_|\\___/ \\___/|_||
|          |___/                  |
|                           v3.0  |
+---by MuhammadRizwan-------------+
        
        """
        self.logo_two = """+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 SigTool v3.0 by MuhammadRizwan    
                                         
        https://TDOhex.t.me            
     https://Android_Patches.t.me      
https://github.com/MuhammadRizwan87
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

        self.meta_data = {
            "Name": "SigTool",
            "Version": "v3.0",
            "Author": "MuhammadRizwan",
            "GitHub Repository": "https://github.com/muhammadrizwan87/sigtool",
            "Telegram Channel": "https://TDOhex.t.me",
            "Second Channel": "https://Android_Patches.t.me",
            "Discussion Group": "https://TDOhex_Discussion.t.me"
        }
    
    def format_with_style(self, text: str, style: str) -> str:
        return f"{self.styles.get(style, '')}{text}{self.styles['endc']}"

    def format_header(self, text: str) -> str:
        return f"\n\n\n{self.styles['bold']}{self.format_with_style(text, 'header')}"

    def format_key(self, text: str) -> str:
        return f"{self.styles['bold']}{self.format_with_style(text, 'key')}"

    def format_value(self, text: str) -> str:
        return self.format_with_style(text, "value")

    def format_divider(self) -> str:
        return self.format_with_style("+-" * 24 + "+", "divider")

    def display_logo_one(self) -> str:
        return self.format_with_style(self.logo_one, "header")
        
    def display_logo_two(self) -> str:
        return self.logo_two

    def get_meta_data(self) -> str:
        meta_lines = [f"{self.format_key(k)}: {self.format_value(v)}" for k, v in self.meta_data.items()]
        meta_content = "\n".join(meta_lines)
        return f"{self.display_logo_two()}\n{self.format_divider()}\n{meta_content}\n{self.format_divider()}"
    
    def format_result(self, key: str, value: str) -> str:
        return f"{self.format_key(key)}: {self.format_value(value)}"
        
    def format_result_two(self, key: str, value: str) -> str:
        return f"\n{self.format_divider()}\n{self.format_key(key)}: \n{self.format_value(value)}\n{self.format_divider()}\n"

    def format_section(self, title: str, results: dict) -> str:
        section_header = self.format_header(title)
        result_lines = [self.format_result(k, v) for k, v in results.items()]
        results_content = "\n\n".join(result_lines)
        return f"{section_header}\n{self.format_divider()}\n{results_content}\n{self.format_divider()}"

    def remove_ansi(self, text: str) -> str:
        ansi_escape = re.compile(r'\x1b[^m]*m')
        return ansi_escape.sub('', text)

    def format_error(self, error_message: str) -> str:
        return self.format_with_style(f"\n{error_message}", 'error')