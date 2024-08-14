# SigTool: APK Signature Analyzer Pro

---

## Overview
**SigTool** is a command-line tool designed to analyze APK signatures and related information. It provides various functionalities such as extracting APK metadata, signature hashes, CRC32 and HashCode values, generating Base64 and PEM encoded certificates, and more.

---

## Features
- **APK Information Extraction**: Extract essential details like app name, package name, version name, and build code from an APK file.

- **Signature Extraction**: Retrieve the APK certificate bytes in hex string format.

- **Hash Calculations**: Generates and displays a wide range of cryptographic hash values such as SHA-1, SHA-224, SHA-256, SHA-356, SHA-512, MD5 from the APK signature.

- **CRC32 and HashCode Calculation**: Compute CRC32 and Java-style HashCode from the APK signature.

- **Smali Bytecode Generation**: Convert the APK signature into a smali byte array format.

- **Base64 Encoding**: Encode signatures and hashes in Base64.

- **PEM Certificate Parsing**: Create and display PEM formatted certificates from the APK signature.

- **Colon and Uppercase Formatting**: Format hashes with colons and convert to uppercase.

- **File Handling Capabilities:** Manages file outputs efficiently, allowing users to save analysis results directly to files

---

### **1. Installation via pip (Recommended):**

You can easily install SigTool using pip:

```bash
pip install sigtool
```

This command will automatically handle the installation of SigTool.

### **2. Custom Build Installation:**

If you prefer to build SigTool from the source:

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/muhammadrizwan87/sigtool.git
   ```

2. **Navigate to the SigTool Directory:**

   ```bash
   cd sigtool
   ```

3. **Install setuptools:**

   ```bash
   pip install setuptools
   ```

4. **Build and Install the Package:**

   ```bash
   python setup.py install
   ```

---

### Requirements

SigTool relies on external tools like `aapt` and `openssl`. You need to ensure these are installed on your system.

- `aapt` (Android Asset Packaging Tool)
  - To install aapt
    ```bash
    apt-get install aapt
    ```
- `openssl`
  - To install openssl
    ```bash
    apt-get install openssl
    ```
    - Or
      ```bash
      pkg install openssl-tool
      ```

---

### **Usage:**

```
usage: sigtool <apk_path> [-a] [-c] [-e] [-f] [-p] [-u] [-o <output_path>]

positional arguments:
  apk_path       Path to the APK file

options:
  -h, --help     show this help message and exit
  -u             Convert output to uppercase
  -c             Add colons to certificate hashes
  -e             Encode output in Base64
  -p             Parse PEM Certificate
  -a             Generate Smali Byte Array
  -f             Print All Information
  -o O           Output results to a specified file path
  -v, --version  Show program's version number and exit
```

**Examples:**

1. **To print the default results:**
   ```
   sigtool /path/to/apk
   ```

2. **To save the default results to a file:**
   ```
   sigtool /path/to/apk -o /path/to/output.txt
   ```

3. **To print the Base64-encoded results:**
   ```
   sigtool /path/to/apk -e
   ```

4. **To save all results to a file:**
   ```
   sigtool /path/to/apk -f -o /path/to/output.bin
   ```

---

## Contributing
Feel free to submit issues or pull requests if you find any bugs or have suggestions for new features.

## License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/muhammadrizwan87/sigtool/blob/main/LICENSE) file for more details.

## Author
MuhammadRizwan
- [TDOhex Telegram](https://TDOhex.t.me)  
- [Android Patches Telegram](https://Android_Patches.t.me)  
- [GitHub](https://github.com/MuhammadRizwan87)

---