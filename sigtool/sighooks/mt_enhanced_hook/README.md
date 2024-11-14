## Features
- Kill Signature Verification from APK Files.

## Usage
**Note**: This hook has been obfuscated to help bypass hook detection.

### To Inject Hook on Target APK

Follow these steps to inject the generated hook into your target APK file.

1. **Decompile the Target APK**:  
   Use a decompiling tool of your choice (such as MT Manager) to decompile the APK file.

2. **Find the Application Class**:  
   Search all `.dex` files for the following pattern:
    ```smali
    .super Landroid/app/Application;
    ```

3. **Modify the Super Class**:  
   Replace each matched result with:
    ```smali
    .super Landroid/app/application;
    ```

4. **Inject Hook Files**:  
   Add all generated hook files into the decompiled target APK.

5. **Re-sign the Hooked APK**:  
   Use a custom keystore or a test keystore to sign the modified APK file. You can use our **[KeySigner](https://github.com/muhammadrizwan87/keysigner)** tool to create a custom keystore and sign the APK.

### Purpose and Flexibility
This module is added for **testing purposes** to help reverse engineers understand the advantages and functionality of **sigtool**. By generating MT enhance hook process, users can gain insights into how sigtool operates. Furthermore, you are free to use this module as a template to create other types of hooks as needed.

## License
This module is based on [ApkSignatureKillerEx by L-JINBIN](https://github.com/L-JINBIN/ApkSignatureKillerEx).