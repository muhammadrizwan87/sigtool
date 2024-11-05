# SigTool: APK Signature and Keystore Analyzer Pro

---

## Overview
**SigTool** is a command-line tool designed to in-depth APK signature and keystore analysis and related information. It provides various functionalities such as extracting APK metadata, signature hashes, CRC32 and HashCode values, generating Base64 and PEM encoded certificates, and more.

---

## Features
- **APK Information Extraction**: Extract essential details like app name, package name, version name, and build code from an APK file.

- **Signature Extraction**: Retrieve the certificate bytes in hex string format from APK file, RSA file and x509 certificate.

    - To extract an x509 certificate from your keystore, you can check out our second tool, **[KeySigner](https://github.com/muhammadrizwan87/keysigner)**.

- **Hash Calculations**: Generates and displays a wide range of cryptographic hash values such as SHA-1, SHA-224, SHA-256, SHA-356, SHA-512, MD5 from the extracted certificate.

- **CRC32 and HashCode Calculation**: Compute CRC32 and Java-style HashCode from the extracted certificate.

- **Smali Bytecode Generation**: Convert the extracted certificate into a smali byte array format.

- **Base64 Encoding**: Encode signatures and hashes in Base64.

- **PEM Certificate Parsing**: Create and display PEM formatted certificates from the extracted certificate.

- **Colon and Uppercase Formatting**: Format hashes with colons and convert to uppercase.

- **File Handling Capabilities:** Manages file outputs efficiently, allowing users to save analysis results directly to files.

- **Generate MT VIP Hook:** SigTool can also generate an MT VIP hook to bypass APK signatures. **[How to Inject the hook?...](https://github.com/muhammadrizwan87/sigtool/tree/main/sigtool/sighooks/mt_enhanced_hook#to-inject-hook-on-target-apk)**

---

## Requirements

Before using SigTool, ensure that the following system dependencies are installed:

1. **Python**: Required to run the SigTool.
2. **Java**: Required to run smali.jar for generating MT hook.
3. **aapt**: Required to extract APK metadata.
4. **OpenSSL**: Required for handling certificates.

---

## Installation

### Termux (Android)

To install SigTool on Termux, use the following command to install all necessary dependencies:

  ```bash
  pkg install python openjdk-17 aapt openssl-tool
  ```

### Installation via pip (Recommended)

You can easily install SigTool using pip:

  ```bash
  pip install --force-reinstall sigtool
  ```

For the latest changes and features, install SigTool directly from the GitHub repository:

  ```bash
  pip install --force-reinstall -U git+https://github.com/muhammadrizwan87/sigtool.git
  ```

### Custom Build Installation

To build SigTool from source:

1. Clone the repository:

    ```bash
    git clone https://github.com/muhammadrizwan87/sigtool.git
    ```

2. Navigate to the SigTool directory:

    ```bash
    cd sigtool
    ```

3. Install the build tools:

    ```bash
    pip install build
    ```

4. Build and install the package:

    ```bash
    python -m build
    pip install --force-reinstall dist/sigtool-2.0-py3-none-any.whl
    ```

---


### **Usage:**

```
usage: sigtool <apk_path> [-a] [-c] [-e] [-f] [-fc] [-fu] [-fuc] [-p] [-u] [-uc] [-hmt] [-o <output_path>]

positional arguments:
  apk_path       Path to the APK file

options:
  -h, --help     show this help message and exit
  -u             Convert output to uppercase
  -c             Add colons to certificate hashes
  -uc            Add colons to hashes and convert output to uppercase
  -e             Encode output in Base64
  -p             Parse PEM Certificate
  -a             Generate Smali Byte Array
  -f             Print All Information
  -fc            Add colons to hashes and print all information
  -fu            Convert output to uppercase and print all information
  -fuc           Add colons to hashes, convert output to uppercase and print all information
  -hmt           Generate and export hook of MT enhanced version
  -o O           Output results to a specified file path. If the path ends with '.json', results will be saved in JSON format.
  -v, --version  Show program's version number and exit
```

**Examples:**

1. **To print the default results:**
    ```badh
    sigtool /path/to/apk
    ```

2. **To save the default results to a file:**
    ```bash
    sigtool /path/to/apk -o /path/to/output.txt
    ```

3. **To print the Base64-encoded results:**
    ```bash
    sigtool /path/to/apk -e
    ```

4. **To save all results to a file:**
    ```bash
    sigtool /path/to/apk -f -o /path/to/output.bin
    ```
5. **To save results in JSON format:**
    ```bash
    sigtool /path/to/apk -f -o /path/to/output.json
    ```

6. **To export hook of MT enhanced version:**
    ```bash
    sigtool /path/to/apk -hmt -o /path/to/hook
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