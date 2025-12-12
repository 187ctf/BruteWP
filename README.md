# BruteWP by 187ctf

## 🚀 Overview

A high-performance WordPress authentication brute-force tool designed for security professionals, penetration testers, and CTF players. Features both command-line and graphical user interfaces with real-time statistics and progress tracking.

## ✨ Features

- ⚡ **Ultra-Fast**: Multi-threaded architecture supporting up to 500 concurrent threads
- 🎨 **Modern GUI**: User-friendly Tkinter interface with real-time progress monitoring
- 📊 **Live Statistics**: Track attack progress, speed (req/s), and elapsed time
- 🎯 **Smart Detection**: Automatic success detection with cookie validation
- 💾 **Auto-Save**: Found credentials automatically saved to file
- 🔒 **No Rate-Limit Mode**: Optimized for servers without rate limiting
- 📝 **Detailed Logging**: Color-coded console output with timestamps
- 🐍 **Pure Python**: No external dependencies except requests and tkinter

## 🎯 Use Cases

- Penetration testing and security audits
- CTF (Capture The Flag) challenges
- WordPress security assessments
- Password strength testing
- Educational purposes and security research

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Users are responsible for complying with applicable laws. Unauthorized access to computer systems is illegal. Use this tool only on systems you own or have explicit permission to test.

## 🛠️ Technical Specifications

- **Language**: Python 3.7+
- **Threading**: ThreadPoolExecutor for optimal performance
- **GUI Framework**: Tkinter (built-in)
- **HTTP Library**: Requests with session management
- **Target**: WordPress wp-login.php authentication
- **Platform**: Cross-platform (Linux, Windows, macOS)

## 📖 Installation & Usage
```bash
# Clone repository
git clone https://github.com/187ctf/BruteWP.git
cd BruteWP

# Install dependencies
pip3 install -r requirements.txt

# GUI version
python3 bruteWP.py


## 🏆 Performance

- **Speed**: 200-1000 requests/second (depending on threads)
- **Efficiency**: Optimized for no-rate-limit scenarios
- **Memory**: Low memory footprint with efficient queue management
- **Scalability**: Linear scaling with thread count

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## 📧 Contact

- Author: 187ctf
- GitHub: [@187ctf](https://github.com/187ctf)

## ⭐ Star History

If you find this tool useful, please consider giving it a star!

---

**For educational and authorized testing purposes only**
```

## 🏷️ Tags/Topics pour GitHub
```
wordpress
brute-force
penetration-testing
security
hacking-tool
ctf
password-cracking
tkinter
python3
multi-threading
cybersecurity
infosec
red-team
security-tools
authentication
ethical-hacking
bug-bounty
wordpress-security
```

## 📋 Description courte pour le repo (280 caractères max)
```
⚡ WordPress Ultra-Fast Brute Forcer - High-performance multi-threaded authentication testing tool with modern GUI. Supports 500+ concurrent threads. Perfect for pentesting, CTF & security audits. CLI + GUI versions. Educational purposes only.
