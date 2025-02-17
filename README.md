
---

# Reconnaissance Automation Tool

The **Reconnaissance Automation Tool** is a powerful, modular tool designed to streamline the reconnaissance process for bug bounty hunters and penetration testers. It automates subdomain enumeration, port scanning, vulnerability detection, cloud asset discovery, and more. The tool also includes a **web-based dashboard** for visualizing results.

---

## Features

+ **Subdomain Enumeration**: Gather subdomains using Amass and Sublist3r.

+ **Port Scanning**: Scan for open ports using Masscan.

+ **Directory Fuzzing**: Discover hidden directories and endpoints using FFuf.

+ **Wayback Machine Integration**: Fetch historical URLs.

+ **Technology Fingerprinting**: Identify technologies used by the target.

+ **Shodan Integration**: Gather information about the target using Shodan.

+ **Cloud Asset Discovery**: Detect misconfigured cloud assets (e.g., AWS S3 buckets).

+ **Vulnerability Scanning**: Scan for common vulnerabilities using Nuclei.

+ **JavaScript Analysis**: Extract endpoints and secrets from JavaScript files.

+ **Web-Based Dashboard**: Visualize results in a user-friendly interface.

---

## Installation

### Prerequisites

+ Python 3.8+

+ Go (for Nuclei and Subjack)

+ Git

### Step 1: Clone the Repository
```
git clone https://github.com/your-username/recon-tool.git
cd recon-tool
```

### Step 2: Set Up a Virtual Environment
```
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Python Dependencies
```
pip install -r requirements.txt
```

### Step 4: Install External Tools

1. **Amass**:

```
go install -v github.com/OWASP/Amass/v3/...@master
```

2. **Sublist3r**:

```
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
cd ..
```

3. **Masscan**:

```
sudo apt install masscan  # On Ubuntu
```

4. **FFuf**:

```
go install github.com/ffuf/ffuf@latest
```

5. **Nuclei**:

```
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

6. **Subjack**:

```
go install github.com/haccer/subjack@latest
```

7. **LinkFinder**:

```
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip install -r requirements.txt
cd ..
```

8. **Cloud_enum**:

```
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip install -r requirements.txt
cd ..
```
---

## Usage

### Step 1: Run the Tool

```
python recon_tool.py -d example.com --shodan-api-key YOUR_SHODAN_API_KEY
```

### Step 2: View Results

+ Results are saved in `recon_results.json` and `recon_results.csv`.

+ To visualize results, start the web-based dashboard:

```
python dashboard.py
```

+ Open your browser and navigate to `http://127.0.0.1:5000`.

---

## Modules

1. **Subdomain Enumeration**
+ Uses Amass and Sublist3r to gather subdomains.

2. **Port Scanning**
+ Uses Masscan to scan for open ports.

3. **Directory Fuzzing**
+ Uses FFuf to discover hidden directories and endpoints.

4. **Wayback Machine Integration**
+ Fetches historical URLs from the Wayback Machine.

5. **Technology Fingerprinting**
+ Identifies technologies using Wappalyzer.

6. **Shodan Integration**
+ Gathers information about the target using Shodan.

7. **Cloud Asset Discovery**
+ Detects misconfigured cloud assets using Cloud_enum.

8. **Vulnerability Scanning**
+ Scans for common vulnerabilities using Nuclei.

9. **JavaScript Analysis**
+ Extracts endpoints and secrets from JavaScript files using LinkFinder.

---

## Web-Based Dashboard

The dashboard provides a user-friendly interface for visualizing results.

### How to Use

1. Run the dashboard:

```
python dashboard.py
```

2. Open your browser and navigate to `http://127.0.0.1:5000`.

---

## Contributing

We welcome contributions! Here’s how you can contribute:

1. Fork the repository.

2. Create a new branch:

```
git checkout -b feature/your-feature-name
```

3. Commit your changes:

```
git commit -m "Add your feature"
```

4. Push to the branch:

```
git push origin feature/your-feature-name
```

5. Open a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](https://chat.deepseek.com/a/chat/s/LICENSE) file for details.

---

## Support

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/your-username/recon-tool/issues).

---

## Acknowledgments

+ [Amass](https://github.com/OWASP/Amass)

+ [Sublist3r](https://github.com/aboul3la/Sublist3r)

+ [Masscan](https://github.com/robertdavidgraham/masscan)

+ [FFuf](https://github.com/ffuf/ffuf)

+ [Nuclei](https://github.com/projectdiscovery/nuclei)

+ [Subjack](https://github.com/haccer/subjack)

+ [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

+ [Cloud_enum](https://github.com/initstring/cloud_enum)

---

Enjoy using the **Reconnaissance Automation Tool**! Happy hacking! 🚀