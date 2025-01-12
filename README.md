# FileEncryptor

## Description
`FileEncryptor` is a simple Windows application that allows users to encrypt and decrypt files using two different algorithms: AES (Advanced Encryption Standard) and RSA (Rivest–Shamir–Adleman). It provides an intuitive GUI where users can select a file, choose an encryption algorithm, and perform encryption or decryption operations.

## Features
- **AES Encryption/Decryption**: Encrypt or decrypt files with a password using the AES algorithm.
- **RSA Encryption/Decryption**: Encrypt or decrypt files using public/private RSA keys.
- **Generate RSA Keys**: Automatically generate RSA public and private keys.
- **File Selection**: Easily select files to encrypt or decrypt through a file chooser dialog.
- **Password Protection**: AES encryption requires a user-defined password for encryption and decryption.

## Prerequisites
To run this application, you need:
- **.NET Framework 4.5** or later (for WPF applications).
- **Visual Studio** (for building or modifying the code).

## Installation
1. Clone or download the repository to your local machine.
```bash
git clone https://github.com/KrzysztofW02/FileEncryptor.git
```
3. Open the solution in Visual Studio.
4. Build the solution by pressing `Ctrl + Shift + B` or selecting **Build > Build Solution**.
5. Run the application by pressing `F5` or selecting **Debug > Start Debugging**.

## Usage
1. **Select Algorithm**: Choose between **AES** or **RSA** for encryption/decryption.
2. **Select File**: Click the "Choose File" button to select a file for encryption or decryption.
3. **Enter Password** (for AES only): Input a password to encrypt or decrypt using AES. This step is skipped for RSA.
4. **Encrypt/Decrypt**: 
- For **AES**, enter the password and click the "Encrypt" or "Decrypt" button.
- For **RSA**, the app will check if RSA keys exist. If not, it will generate them. After that, click the "Encrypt" or "Decrypt" button.

The encrypted or decrypted file will be saved in the same directory as the original file with a suffix indicating the action performed (`(encrypted)` or `(decrypted)`).

## RSA Key Generation
- RSA keys are generated automatically the first time the app runs or if no keys are found in the `Keys` directory.
- The public and private keys are saved as `publicKey.pem` and `privateKey.pem` inside the `Keys` directory within the application's root folder.
