Python Automated Security Testing Tool
Overview
This Python-based security testing tool is designed to help identify vulnerabilities in websites and web applications. It performs a range of tests, simulating common cyberattacks, to provide a comprehensive security assessment. This tool is for ethical hacking and authorized penetration testing purposes only.
Features
The tool provides the following functionalities:
Vulnerability Scanning:
SQL Injection (SQLi) testing
Cross-Site Scripting (XSS) testing
Cross-Site Request Forgery (CSRF) testing
Directory Traversal testing
Command Injection testing
File Upload Exploits testing
Login Brute-Force: Attempts to crack login forms using provided username and password lists.
Port Scanning: Scans for open ports and running services on the target host.
Unauthorized Access: Attempts to access sensitive directories and files.
Website Crawling: Crawls the website to discover endpoints, forms, and input fields.
Reporting: Generates a detailed report of found vulnerabilities, their severity, and suggested remediation steps.
Requirements
Python 3.x
Required Python libraries:
requests
BeautifulSoup4
Installation
Install Python 3.x.
Install the required Python libraries:
pip install requests beautifulsoup4


Usage
Clone the repository (if applicable) or save the main.py script.
Run the script from the command line:
python main.py


The script will prompt you for the following information:
Target URL: The URL of the website or web application to test (e.g., https://example.com).
Crawl the website?: Enter yes to crawl the site for endpoints and forms, or no to test only the target URL.
Path to username list file (optional for brute-force): The path to a file containing a list of usernames (one per line) for the login brute-force attack.
Path to password list file (optional for brute-force): The path to a file containing a list of passwords (one per line) for the login brute-force attack.
The script will perform the security tests and display a summary report on the console. A more detailed report will also be saved to a text file in the reports directory.
Report
The tool generates a report in a text file (located in the reports directory) with a filename that includes a timestamp. The report contains the following information:
Target URL
Start and end times of the test
Test duration
Detailed results for each test, including:
Test name
Status (Vulnerable, Safe, Error, Skipped)
Message describing the result
Any relevant data (e.g., vulnerable URL, payload used)
Disclaimer
This tool is for ethical hacking and authorized penetration testing purposes only.
Unauthorized use of this tool is strictly prohibited.
Always obtain explicit permission before testing any system.
The author is not responsible for any misuse of this tool.
This tool is provided as-is, without any warranty.
Further Improvements
Integrate more advanced vulnerability scanning tools (e.g., Nmap, sqlmap, OWASP ZAP).
Implement more sophisticated crawling.
Add support for more authentication methods.
Develop a more user-friendly interface (e.g., GUI or web interface).
Create more detailed and customizable report formats (e.g., HTML, JSON).
Implement post-exploitation testing.
Add more test cases and payloads for each vulnerability type.
Implement rate limiting.
Add proxy support.
