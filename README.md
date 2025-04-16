![2025-04-17_01-49](https://github.com/user-attachments/assets/2a8deb62-957e-43a7-a41e-c9aaf3a39990)



# Dragon Recon is an OSINT (Open-Source Intelligence) tool designed for domain reconnaissance and security analysis.

# What Does It Do?
Subdomain Enumeration via crt.sh
Dragon Recon leverages the publicly available service crt.sh to search for SSL/TLS certificate data, extracting domain names and subdomains associated with the target domain. This helps you identify additional subdomains that may be publicly exposed.

# Brute-force Subdomain Discovery
The tool uses a wordlist (provided in a file called subdomains.txt) and performs a brute-force check to discover additional subdomains. It attempts to resolve each prefix (e.g., “www,” “mail,” “api”) combined with the target domain using DNS queries. Any successfully resolved hostnames are considered valid subdomains.

# Shodan Integration
By incorporating the Shodan API, Dragon Recon can retrieve further information on the IP addresses obtained from the brute-force process. Shodan is a search engine that indexes devices connected to the Internet. With this integration, the tool displays details such as the operating system, open ports, and organizational information linked to each discovered IP.

# Results Storage
Users can save the results—subdomains found via crt.sh, brute-force subdomains, and Shodan data—to files in both TXT and JSON formats. This makes it easy for analysts or security professionals to review the gathered data later or integrate it into further automated processes.

# Curses-Based Interactive Interface
Dragon Recon features an interactive text-based user interface built with Python’s curses module. The interface is designed with a red-themed color scheme and ASCII art branding to create a visually engaging command-line experience. It provides a menu-driven navigation system allowing users to choose from various functions (e.g., set the target domain, initiate subdomain scanning, view results, and save reports).

# In Summary
Dragon Recon is a multi-functional OSINT tool that automates the process of gathering intelligence on a domain by:

Enumerating subdomains using public certificate data.

Discovering additional subdomains through brute-force methods.

Enhancing the reconnaissance by incorporating detailed IP information through Shodan.

Offering an interactive, terminal-based interface to guide the user through each step.

Allowing the export of reports for further analysis.

This tool is especially useful for penetration testers, security researchers, and network administrators who need to perform comprehensive reconnaissance on a target domain using open-source data.

# Dragon Recon

Dragon Recon is an OSINT tool for domain reconnaissance. It can enumerate subdomains via crt.sh, perform brute-force subdomain discovery (using a wordlist), and retrieve IP information from Shodan. The tool uses a curses-based interface to provide an interactive command-line experience.

## Features

- **Subdomain Enumeration:** Find subdomains using crt.sh.
- **Brute-force Subdomains:** Discover subdomains by trying wordlist prefixes.
- **Shodan Integration:** Look up IP information with the Shodan API.
- **Report Generation:** Save results to TXT and JSON files.
- **Interactive UI:** Curses-based, colorful, and paginated menu interface.

## Requirements

- Python 3.6 or higher.
- [Requests](https://pypi.org/project/requests/)  
- **For Unix/Linux/macOS:** The `curses` module is included by default.  
- **For Windows users:** Install [`windows-curses`](https://pypi.org/project/windows-curses/) to support the curses module.

## Installation

1. **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3. **Prepare your wordlist:**
   
   Ensure you have a file named `subdomains.txt` in the repository root containing your subdomain prefixes (one per line).


4. **Run the tool:**

    ```bash
    python3 Dragon_Recon.py
    ```

## Usage

When you run the tool, you will see an interactive menu where you can:

- Set or change the target domain.
- Search for subdomains via crt.sh.
- Perform brute-force subdomain discovery.
- Scan the discovered IPs using Shodan.
- Save the gathered results into TXT and JSON files.

Follow the on-screen prompts to interact with the tool.

## License

*Include your license information here.*

## Contact

For support or inquiries, please visit:
- **Support:** [https://linktr.ee/pyscodes](https://linktr.ee/pyscodes)
- **Contact:** [https://instagram.com/pyscodes](https://instagram.com/pyscodes)
