# Information Security Assignment

This repository contains two main components as part of the CSD356 Foundation of Information Security assignment:

1. A secure password manager implementation
2. Password cracking demonstration using HASHCAT

## Part 1: Secure Password Manager

A Python-based password manager application with AES encryption and a graphical user interface built with CustomTkinter.

### Features

- **AES-256 Encryption**: All passwords stored in the vault are encrypted using industry-standard encryption
- **Master Password Authentication**: Access to the password vault requires a master password
- **Password Generation**: Automatically generate strong random passwords
- **Password Strength Checking**: Evaluates password strength using the zxcvbn library
- **User-Friendly Interface**: Modern UI with password visibility toggle

### Project Structure

```
password_manager/
│
├── src/
│   ├── encryption.py       # Encryption logic using AES
│   ├── password_generator.py  # Password generation functionality
│   ├── password_checker.py    # Password strength checking
│   └── vault.py            # Password vault management
│
├── main.py                 # Main application entry point
├── requirements.txt        # Project dependencies
└── README.md               # Project documentation
```

### Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

### Usage

1. **First Time Setup**:
   - Click "Create New Vault" to set up your password manager
   - Create a strong master password (recommended: mix of uppercase, lowercase, numbers, and special characters)

2. **Login**:
   - Enter your master password to access your vault
   - Use the Show/Hide toggle to verify correct password entry

3. **Adding Passwords**:
   - Enter the service name, username, and password
   - Optionally use the "Generate Strong Password" button
   - Click "Save Password" to encrypt and store the credentials

4. **Retrieving Passwords**:
   - In the "Retrieve Password" section, enter the service name
   - Click "Retrieve Password" to decrypt and display the stored credentials

### Security Features

- **Key Derivation**: PBKDF2 with SHA-256 and 100,000 iterations for generating encryption keys
- **Salt Generation**: Unique salt for each vault to prevent rainbow table attacks
- **AES-GCM Encryption**: Used via the Fernet implementation in the cryptography library
- **Password Strength Evaluation**: Uses zxcvbn for realistic password strength assessment

## Part 2: HASHCAT Password Cracking Demonstration

This section provides a demonstration of password cracking using HASHCAT with a custom password dictionary.

### Components

1. **Password Dictionary Creation**: Either custom-generated or downloaded
2. **SHA-1 Hash Generation**: Converting plaintext passwords to SHA-1 hashes
3. **HASHCAT Execution**: Attempting to recover passwords from their hashes
4. **Success Rate Analysis**: Measuring the effectiveness of the cracking process

### Setup Instructions

1. Install HASHCAT:
```bash
# For Ubuntu/Debian
sudo apt-get install hashcat

# For Windows
# Download from https://hashcat.net/hashcat/
```

2. Create or download a password dictionary

3. Generate SHA-1 hashes using the provided script:
```bash
python generate_hashes.py --input dictionary.txt --output hashes.txt
```

4. Run HASHCAT to crack the passwords:
```bash
hashcat -m 100 -a 0 hashes.txt dictionary.txt
```

5. Calculate success rate:
```bash
python calculate_success.py --input hashes.txt --cracked hashcat.potfile
```

### Hash Generation Script and Success Rate

Run the `hash.py` script to generate SHA-1 hashes from a list of passwords. The script will output the hashes to a file.

It'll calculate the success rate by comparing the number of successfully cracked passwords to the total number of hashes.

```bash
python hash.py --input dictionary.txt --output hashes.txt
```


## Submission Requirements

### Part 1: Password Manager
- [x] Well-documented source code with comments
- [x] Short report describing encryption technique and security considerations
- [x] Example usage and test cases
- [x] Bonus: User interface

### Part 2: HASHCAT Usage
- [ ] Screenshot of generated passwords
- [ ] Screenshot of hashed passwords
- [ ] HASHCAT command for cracking
- [ ] Success rate with screenshot

## Author

[Your Name]

## Acknowledgments

- CustomTkinter for the modern UI components
- Cryptography library for secure encryption
- zxcvbn for password strength evaluation