# Secure Chat Application with Encryption

## Project Overview

This project is a Python-based secure chat application developed using TCP socket programming.

The application provides:

- User authentication
- Multi-client communication
- X25519 key exchange
- AES-256-GCM encryption
- End-to-end encrypted messaging
- Graphical User Interface using Tkinter
- Password hashing using PBKDF2-HMAC-SHA256

## Features

1. Secure TCP communication
2. User registration
3. User login
4. Password hashing
5. Multi-client chat
6. X25519 key exchange
7. HKDF-SHA256 key derivation
8. AES-256-GCM encryption
9. End-to-end encrypted messages
10. GUI interface

## Technologies Used

- Python 3
- TCP/IP
- Python socket
- Threading
- Tkinter
- Cryptography library

## Project Structure

```text
Secure-Chat-Application/
├── server.py
├── client.py
├── auth.py
├── crypto_utils.py
├── requirements.txt
├── README.md
└── .gitignore