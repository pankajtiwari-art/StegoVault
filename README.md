# StegoVault
### An Advanced Browser-Based Steganography Tool

StegoVault is a self-contained browser application for performing secure steganography operations directly inside a web browser. Unlike traditional tools that require installation, StegoVault runs entirely on the client side using modern JavaScript APIs.

The project combines several security paradigms:

- Military-style steganography (hiding data within plain sight)
- Plausible deniability systems inspired by tools like VeraCrypt
- Browser-based cryptography using the Web Crypto API
- Zero-width character encoding for text-based steganography

The tool evolved from earlier image-based steganography tools into a modern **text-based hidden messaging system** that works across social media, messaging platforms, and email.

---

# Run Code

<details>
<summary>Click to run the project</summary>

https://pankajtiwari-art.github.io/StegoVault/

</details>

---

# What is Steganography?

Steganography comes from the Greek words **steganos** (covered) and **graphia** (writing).

It is the practice of hiding information inside other data so that the existence of the hidden message is concealed.

Unlike cryptography, which makes data unreadable, steganography hides the fact that data exists at all.

StegoVault focuses on **text steganography**, embedding secret information inside ordinary-looking text.

---

# Core Technical Architecture

## Single File Design

The entire application exists inside a single HTML file that contains:

- HTML structure (user interface)
- CSS styling (cyberpunk themed interface)
- JavaScript logic (cryptography and steganography engine)

Benefits of this architecture:

- No external dependencies
- Fully offline operation
- Easy distribution
- No installation required

---

# Key Technologies Used

| Technology | Purpose | Implementation |
|-----------|--------|---------------|
| Web Crypto API | Encryption & decryption | AES-GCM with PBKDF2 |
| Zero-Width Characters | Hidden data encoding | Unicode characters |
| Compression API | Data size optimization | Gzip compression |
| Canvas API | Visual interface effects | Matrix-style animation |
| Clipboard API | Text transfer | Copy hidden messages |

---

# How It Works

## Encryption Process

1. User inputs:
   - Cover text
   - Secret message
   - Password
   - Optional decoy message
   - Optional TTL value

2. Data processing pipeline
   - Secret Message → JSON → Compression → Encryption → Binary Data
3. Dual-layer packaging

- Real payload encrypted with main password
- Decoy payload encrypted with decoy password

4. Steganographic embedding

Binary data is converted into invisible Unicode characters and embedded inside the cover text.

---

## Decryption Process

1. Extract hidden characters from the text
2. Convert characters back into binary data
3. Attempt password-based decryption
4. Verify integrity
5. Display hidden message

---

# Steganography Method

StegoVault uses invisible Unicode characters:

| Character | Meaning |
|-----------|---------|
| U+200B | Binary 0 |
| U+200C | Binary 1 |
| U+2060 | Start/End markers |

Example:

Normal text
HELLO WORLD

Text with hidden data
The hidden characters are invisible but encode binary data.

---

# Cryptographic Implementation

### Key Derivation

- PBKDF2
- 100,000 iterations
- SHA-256 hash

### Encryption

- Algorithm: AES-GCM
- Key size: 256-bit
- IV length: 12 bytes
- Authentication tag: 16 bytes

### Integrity Verification

- SHA-256 checksum of plaintext
- First 8 bytes stored with encrypted payload
- Verified during decryption

---

# Dual Layer Security System

## Real Layer

- Contains the real secret message
- Accessed using the main password
- Optional TTL auto-destruction

## Decoy Layer

- Contains harmless fake data
- Accessed with decoy password

This allows **plausible deniability** if a password must be revealed.

---

# Major Features

### Browser-Based Cryptography

- Uses the Web Crypto API
- No server interaction
- Works offline

### Social Media Resistant

Zero-width characters often survive text filtering on messaging platforms.

### Visual Security Indicators

- Password strength meter
- Hacker-style decryption animation
- Matrix-style background effect

### Operational Security

- Panic wipe mode
- Clipboard auto-copy
- No persistent storage

---

# Security Analysis

## Strengths

- Client-side encryption
- Invisible steganographic encoding
- Dual-layer deniability
- AES-256 encryption

## Limitations

- Requires modern browsers
- Some platforms strip invisible characters
- Advanced forensic analysis may detect hidden data

---

# Threat Model

### Protected Against

- Casual observation
- Message interception
- Basic forensic inspection
- Platform filtering

### Not Protected Against

- Advanced steganalysis
- Targeted investigation
- Compromised devices

---

# Use Cases

### Journalism
Secure communication between journalists and sources.

### Human Rights Work
Hidden communication in surveillance environments.

### Corporate Security
Secure credential sharing.

### Personal Privacy
Private notes hidden in ordinary text.

---

# Comparison With Traditional Tools

| Feature | StegoVault | Traditional Tools |
|-------|-------------|------------------|
| Platform | Browser | Desktop software |
| Portability | Single file | Installed program |
| Steganography | Text-based | Mostly image-based |
| Deniability | Dual layer | Usually single layer |

---

# Future Development

Possible future improvements include:

- Image and audio steganography
- Post-quantum cryptography
- Mobile application version
- Plugin architecture

---

# Author

**Pankaj Tiwari**
