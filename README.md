# StegoVault
StegoVault: An Advanced Browser-Based Steganography Tool

1. Introduction and Origin

StegoVault is a sophisticated, self-contained web application designed for secure, offline steganography operations. Unlike traditional steganography tools that require software installation, this tool operates entirely within a web browser using modern JavaScript APIs. The concept originated from combining several security paradigms:  (paradaem)

1. Military-grade steganography (hiding data within plain sight)
2. Plausible deniability systems (inspired by VeraCrypt and similar tools)
3. Browser-based cryptography (using Web Crypto API)
4. Zero-width character encoding (a modern text-based steganography method)

The tool represents evolution from earlier versions that focused primarily on image-based steganography to text-based methods that work across digital platforms including social media, messaging apps, and email.

2. What is Steganography?

Steganography (from Greek steganos meaning "covered" and graphia meaning "writing") is the practice of concealing information within other non-secret data. Unlike cryptography (which makes data unreadable), steganography makes data invisible. This tool implements text steganography - hiding secret messages within ordinary-looking text.

3. Core Technical Architecture

3.1 Single-File Design

The entire application exists in one HTML file containing:

· HTML structure (UI layout)
· CSS styling (cyberpunk-themed interface)
· JavaScript logic (all cryptographic and steganographic operations)

This design ensures:

· No external dependencies
· Complete offline functionality
· Easy distribution and portability
· No installation required

3.2 Key Technologies Used

Technology Purpose Implementation
Web Crypto API Encryption/decryption AES-GCM with PBKDF2 key derivation
Zero-Width Characters Data hiding Unicode characters U+200B, U+200C
Compression API Data optimization Gzip compression for payload
Canvas API Visual effects Matrix-style background animation
Clipboard API Data transfer Copying steganographic text

4. How It Works: Technical Breakdown

4.1 The Encryption Process

When you encrypt a message:

```
1. Input Collection:
   - Cover text (innocent-looking text)
   - Secret message (actual hidden data)
   - Password (encryption key)
   - Optional: Decoy message and password
   - Optional: TTL (Time-To-Live) value

2. Data Processing:
   - Secret message → JSON string → Gzip compression
   - Password → PBKDF2 key derivation (100,000 iterations)
   - Encryption using AES-GCM (Galois/Counter Mode)
   - Integrity hash calculated (SHA-256, first 8 bytes)

3. Dual-Layer Packaging:
   - Real payload encrypted with main password
   - Decoy payload encrypted with decoy password (or random data)
   - Both combined with length prefixes and salt

4. Steganographic Embedding:
   - Binary data converted to zero-width characters
   - Hidden between invisible markers (U+2060, U+200B, U+200C)
   - Embedded within cover text
   - Final text appears normal to human eyes
```

4.2 The Decryption Process

When you decrypt:

```
1. Extraction:
   - Parse input text for invisible markers
   - Extract zero-width characters
   - Convert back to binary data

2. Unpacking:
   - Extract salt (16 bytes)
   - Read length prefix (4 bytes)
   - Separate real and decoy payloads

3. Decryption Attempts:
   - Try main password on real payload
   - If fails, try decoy password on decoy payload
   - Verify integrity checksum

4. Result Display:
   - Hacker-style animated reveal
   - TTL countdown display (if active)
   - Integrity verification status
```

4.3 The Steganography Method: Zero-Width Characters

The tool uses Unicode zero-width characters which are invisible when rendered:

· U+200B (Zero Width Space) = Binary 0
· U+200C (Zero Width Non-Joiner) = Binary 1
· U+2060 (Word Joiner) = Start/end markers

Example:

```
Normal text: "Hello World"
With hidden data: "Hello‌‍World" (contains invisible characters)
```

Binary data (01101001) becomes: U+200C U+200B U+200B U+200C U+200B U+200C U+200C U+200B

4.4 Cryptographic Implementation

Key Derivation:

```javascript
// PBKDF2 with 100,000 iterations
const key = await crypto.subtle.deriveKey(
  {name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256"},
  baseKey,
  {name: "AES-GCM", length: 256},
  false,
  ["encrypt", "decrypt"]
);
```

Encryption:

· Algorithm: AES-GCM (authenticated encryption)
· Key size: 256-bit
· IV: 12 bytes (random)
· Authentication tag: 16 bytes (included automatically by GCM)

Integrity Protection:

· SHA-256 hash of compressed plaintext
· First 8 bytes stored with ciphertext
· Verified during decryption

4.5 Dual-Layer Security System

Real Layer:

· Contains actual secret message
· Accessed with main password
· Optional TTL for auto-destruction

Decoy Layer:

· Contains harmless fake message
· Accessed with decoy password
· Provides plausible deniability under coercion

Security Benefit: If forced to reveal password, user gives decoy password which reveals harmless message while real secret remains protected.

5. Novel Features and Improvements

5.1 What's New in v6.0

Feature Previous Versions v6.0 Improvement
Platform Desktop applications Browser-based, cross-platform
Steganography Method Image-based LSB Text-based zero-width characters
Encryption Basic AES AES-GCM with integrity verification
Deniability Single layer Dual-layer (real+decoy) system
Data Lifetime Permanent TTL-based auto-destruction
Distribution File sharing Copy-paste text or QR codes

5.2 Innovative Features

1. Browser-Based Cryptography
   · Uses Web Crypto API (native browser security)
   · No server involvement
   · Works offline completely
2. Social Media Resistant
   · Zero-width characters survive most platform sanitization
   · Text appears normal on Facebook, Twitter, WhatsApp
   · No suspicious file attachments
3. Visual Security Indicators
   · Real-time password strength meter
   · Data embedding efficiency visualization
   · Hacker-style decryption animation
   · Matrix background effect
4. Operational Security Features
   · Panic mode (double ESC to wipe everything)
   · Auto-copy to clipboard
   · No data persistence (runs in memory)
   · Template system for common cover texts

5.3 Technical Innovations

1. Compressed Encryption Payload
   · Data compressed before encryption
   · Reduces steganographic footprint
   · Better resistance to detection
2. Binary-to-Zero-Width Encoding
   · Efficient 1:1 bit-to-character mapping
   · No data expansion (unlike Base64)
   · Platform-compatible encoding
3. Self-Contained Design
   · All libraries embedded
   · No network requests
   · Under 300KB total size

6. Security Analysis

6.1 Strengths

1. End-to-End Encryption
   · Keys never leave browser
   · No server trust required
   · Client-side only processing
2. Steganographic Security
   · Zero-width characters invisible to humans
   · Survives text-based platforms
   · No statistical anomalies in text
3. Operational Security
   · Plausible deniability via decoy layer
   · TTL-based auto-destruction
   · Panic wipe functionality
4. Cryptographic Strength
   · AES-256 with GCM mode
   · PBKDF2 with 100k iterations
   · Integrity verification

6.2 Limitations

1. Browser Dependency
   · Requires modern browser with Web Crypto API
   · JavaScript must be enabled
   · Mobile browser compatibility varies
2. Platform Limitations
   · Some platforms strip zero-width characters
   · Character limit constraints on some apps
   · Text-only medium required
3. Detection Possibilities
   · Forensic analysis can detect zero-width characters
   · Unusual character sequences may raise flags
   · Not resistant to targeted analysis

6.3 Threat Model

Protected Against:

· Casual observation
· Platform content filters
· Basic forensic examination
· Coercion (via decoy layer)
· Data interception (encrypted)

Not Protected Against:

· Advanced steganalysis
· Targeted investigation with character analysis
· Physical access to unlocked device
· Keylogger malware

7. Use Cases and Applications

7.1 Legitimate Uses

1. Journalist-Source Communication
   · Secure messaging through public platforms
   · Deniability if messages intercepted
2. Human Rights Activism
   · Communication in surveilled regions
   · Hidden messages in public posts
3. Corporate Security
   · Secret sharing of credentials
   · Secure communication bypassing filters
4. Personal Privacy
   · Private notes hidden in plain sight
   · Secure sharing of sensitive information

7.2 Technical Applications

1. Digital Watermarking
   · Embedding ownership information in text
   · Content authentication
2. Covert Communication Channels
   · Backup communication methods
   · Emergency information sharing
3. Security Research
   · Studying steganography methods
   · Cryptographic implementation testing

8. Comparison with Existing Tools

Feature StegoVault v6.0 Traditional Tools
Platform Browser-based Desktop applications
Portability Single HTML file Installation required
Steganography Type Text-based Mostly image-based
Deniability Built-in dual-layer Usually single-layer
Accessibility Runs anywhere OS-dependent
Learning Curve User-friendly GUI Command-line often

Advantages over traditional tools:

· No installation required
· Cross-platform compatibility
· Modern cryptographic standards
· Better user interface
· Social media compatibility

9. Implementation Details for Researchers

9.1 Code Structure

```
StegoVault v6.0 Architecture:
├── HTML Structure (UI Layout)
├── CSS Styling (Cyberpunk Theme)
├── JavaScript Modules:
│   ├── App Core
│   ├── Crypto Module (Web Crypto API)
│   ├── Stego Module (Zero-width encoding)
│   ├── UI Controller
│   ├── Logger System
│   └── Visual Effects
└── Embedded Resources
```

9.2 Key Functions

1. Stego.embed() - Hides data in text
2. Stego.extract() - Extracts hidden data
3. Crypto.encrypt() - Encrypts with AES-GCM
4. Crypto.decrypt() - Decrypts and verifies
5. Utils.compress() - Gzip compression
6. Actions.encrypt() - Full encryption pipeline
7. Actions.decrypt() - Full decryption pipeline

9.3 Data Flow

```
Encryption Flow:
User Input → Compression → Encryption → 
Zero-width Encoding → Embed in Cover Text → Output

Decryption Flow:
Stego Text → Extract Zero-width → Decode Binary → 
Decryption → Decompression → Verify Integrity → Output
```

10. Future Development Directions

1. Enhanced Steganography
   · Support for more Unicode hiding methods
   · Image steganography integration
   · Audio steganography capabilities
2. Improved Security
   · Support for Argon2 key derivation
   · Post-quantum cryptography options
   · Better resistance to steganalysis
3. Additional Features
   · File attachment support
   · Network distribution methods
   · Mobile app version
   · Plugin architecture
4. Research Applications
   · Steganalysis training tool
   · Cryptographic benchmark platform
   · Security education resource



StegoVault 6.0 represents a significant advancement in accessible, secure steganography tools. By leveraging modern web technologies, it brings sophisticated cryptographic and steganographic capabilities to everyday users without requiring technical expertise or software installation.

The tool's innovative features—particularly its dual-layer security system, TTL-based auto-destruction, and use of zero-width character encoding—address real-world security needs while maintaining usability. Its browser-based nature makes it uniquely positioned for scenarios where traditional security tools are impractical or unavailable.

For researchers, this implementation provides a valuable case study in client-side cryptography, modern steganography techniques, and usable security design. The open, inspectable codebase serves as both a practical tool and educational resource for understanding how these security technologies work in practice.

The development demonstrates that robust security tools can be both accessible and powerful, bringing enterprise-grade security paradigms to personal use through thoughtful design and implementation of modern web standards.
