IOC Extractor

A lightweight Python tool for extracting common Indicators of Compromise (IOCs) from text files.

The project is designed as a small cybersecurity/DFIR utility for identifying potentially useful artifacts such as IP addresses, URLs, domains, email addresses, and file hashes during security investigations.

Features

- Extract IPv4 addresses
- Extract URLs
- Extract email addresses
- Extract domain names
- Extract MD5, SHA-1, and SHA-256 hashes
- Remove duplicate indicators automatically
- Calculate the SHA-256 hash of the analyzed file
- Command-line interface
- Uses only Python's standard library

Requirements

- Python 3.8+

No external Python packages are required.

Installation

Clone the repository:

git clone https://github.com/YOUR-USERNAME/ioc-extractor.git
cd ioc-extractor

No additional dependencies are required.

Usage

Run the tool against a text file:

python3 ioc_extractor.py sample.txt

Example output:

[*] Analyzing: sample.txt
[*] File SHA-256: ...

=== IOC EXTRACTION REPORT ===

IPs:
  - 10.10.14.23
  - 192.168.1.50

URLs:
  - http://malicious-example.com/update

Emails:
  - analyst@example.com

Hashes:
  - d41d8cd98f00b204e9800998ecf8427e

Total IOCs: 5

Supported IOC Types

IOC| Examples
IPv4| "192.168.1.50"
URL| "http://example.com/file"
Email| "analyst@example.com"
Domain| "example.com"
MD5| "32 hexadecimal characters"
SHA-1| "40 hexadecimal characters"
SHA-256| "64 hexadecimal characters"

Project Structure

ioc-extractor/
├── ioc_extractor.py
├── sample.txt
├── README.md
└── .gitignore

How It Works

The program reads the supplied text file and uses regular expressions to identify patterns associated with common IOCs.

Extracted indicators are stored in Python sets, which automatically prevent duplicate results.

The program then organizes the results by IOC type and displays them in a readable report.

The analyzed file is also hashed using SHA-256 so that its integrity can be verified later.

Example Use Cases

This tool can be useful for practicing basic security automation and understanding how analysts extract indicators from:

- Security logs
- Incident reports
- Malware-analysis notes
- Suspicious emails
- Threat-intelligence reports
- CTF challenge files

Limitations

This is an intentionally simple educational project.

The current version does not provide:

- IPv6 detection
- Advanced URL parsing
- Malware reputation checks
- Threat-intelligence API integration
- Real-time monitoring
- Recursive directory scanning
- Advanced domain validation

These are potential improvements for future versions.

Future Improvements

Planned improvements include:

- [ ] JSON output
- [ ] CSV output
- [ ] IPv6 extraction
- [ ] Defanged IOC support such as "192[.]168[.]1[.]50"
- [ ] Recursive directory scanning
- [ ] Configurable IOC types
- [ ] Unit tests
- [ ] Threat-intelligence API integration
- [ ] Improved reporting

Disclaimer

This project is intended for educational and defensive security purposes.

Only analyze files and systems that you own or have explicit permission to investigate.

License

MIT License
