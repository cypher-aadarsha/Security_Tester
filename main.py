import concurrent.futures  # For parallelization
import logging
import os
import socket
import time
import urllib.parse
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SecurityTest:
    """
    A modular class for performing various security tests.
    """

    def __init__(self, target_url, report_dir="reports"):
        """
        Initializes the SecurityTest object.

        Args:
            target_url (str): The URL of the target website or web application.
            report_dir (str, optional): Directory to save reports. Defaults to "reports".
        """
        self.target_url = target_url.rstrip('/')  # Remove trailing slash for consistency
        self.session = requests.Session()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        self.session.headers.update(self.headers)
        self.report_dir = report_dir
        self.log_filename = f"{self.report_dir}/security_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.report = {}  # Dictionary to store test results
        self.create_report_directory()
        self.setup_logging()
        self.MAX_THREADS = 10 # Define a constant for max threads

    def create_report_directory(self):
        """Creates the report directory if it doesn't exist."""
        if not os.path.exists(self.report_dir):
            try:
                os.makedirs(self.report_dir)
            except OSError as e:
                print(f"Error creating report directory: {e}")
                # Consider raising an exception or exiting if the directory cannot be created.
                self.report_dir = "." # Fallback to current directory

    def setup_logging(self):
        """Sets up logging to a file."""
        logging.basicConfig(
            filename=self.log_filename,
            level=logging.INFO,
            format="[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Starting security test on {self.target_url}")

    def log_result(self, test_name, status, message, data=None):
        """
        Logs the result of a test and stores it in the report dictionary.

        Args:
            test_name (str): The name of the test.
            status (str): The status of the test ("Vulnerable", "Safe", "Error", "Skipped").
            message (str): A description of the test result.
            data (dict, optional): Any additional data to be included in the report.
        """
        self.logger.info(f"{test_name}: {status} - {message}")
        self.report[test_name] = {
            "status": status,
            "message": message,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "data": data,
        }

    def get_page_content(self, url, method='GET', data=None, allow_redirects=True):
        """
        Retrieves the content of a given URL.

        Args:
            url (str): The URL to retrieve.
            method (str, optional): HTTP method ('GET', 'POST', etc.). Defaults to 'GET'.
            data (dict, optional): Data to send with the request (for POST, etc.). Defaults to None.
            allow_redirects (bool): Whether to follow redirects. Defaults to True

        Returns:
            str: The content of the page, or None on error.
        """
        try:
            response = self.session.request(method, url, data=data, timeout=10, allow_redirects=allow_redirects, verify=False) # added verify=False
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return response.text
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching {url}: {e}")
            self.log_result("URL Fetch", "Error", f"Failed to fetch URL: {url} - {e}")
            return None
        except Exception as e:
            self.logger.error(f"An unexpected error occurred while fetching URL: {url} - {e}")
            self.log_result("URL Fetch", "Error", f"Unexpected error fetching URL: {url} - {e}")
            return None

    def extract_forms(self, html_content, base_url):
        """
        Extracts forms from the HTML content.

        Args:
            html_content (str): The HTML content to parse.
            base_url (str): The base URL of the page.

        Returns:
            list: A list of dictionaries, where each dictionary represents a form
                  and contains the form's action URL, method, and input fields.
        """
        forms = []
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            form_tags = soup.find_all("form")
            for form in form_tags:
                form_details = {}
                action = form.get("action")
                if action:
                    form_details["action"] = urllib.parse.urljoin(base_url, action)  # Use urljoin
                else:
                    form_details["action"] = base_url
                form_details["method"] = form.get("method", "GET").upper()
                form_details["inputs"] = []
                input_tags = form.find_all("input")
                for input_tag in input_tags:
                    input_details = {
                        "name": input_tag.get("name"),
                        "type": input_tag.get("type", "text"),
                        "value": input_tag.get("value", ""),
                    }
                    form_details["inputs"].append(input_details)
                forms.append(form_details)
        except Exception as e:
            self.logger.error(f"Error extracting forms: {e}")
            self.log_result("Form Extraction", "Error", f"Failed to extract forms: {e}")
            return []
        return forms

    def test_sqli(self, url, html_content=None):
        """
        Performs SQL Injection testing on a given URL and its forms.

        Args:
            url (str): The URL to test.
            html_content (str, optional): If the content for the specified url is already fetched.
        """
        self.log_result("SQL Injection", "Skipped", "Starting SQL Injection test...")
        if html_content is None:
          html_content = self.get_page_content(url)
        if html_content is None:
            self.log_result("SQL Injection", "Error", "Failed to retrieve page content.")
            return

        forms = self.extract_forms(html_content, url)
        if not forms:
            self.log_result("SQL Injection", "Safe", "No forms found on the page.")

        sqli_payloads = [
            "'",
            "\"",
            "';",
            "\";",
            "OR 1=1",
            "OR '1'='1",
            "OR \"1\"=\"1\"",
            "1=1",
            "admin'--",
            "admin'#",
            "admin'/*",
            "') OR '1'='1'--",
            "\" OR \"1\"=\"1\"--",
        ]

        for form in forms:
            for payload in sqli_payloads:
                data = {}
                for input_field in form["inputs"]:
                    if input_field["type"] != "submit" and input_field["name"]:
                        data[input_field["name"]] = payload
                response_content = self.get_page_content(form["action"], form['method'], data)
                if response_content:
                  if (
                      "You have an error in your SQL syntax" in response_content
                      or "Warning: mysql" in response_content.lower()
                      or "Unclosed quotation mark after the character string"
                      in response_content
                  ):
                      self.log_result(
                          "SQL Injection",
                          "Vulnerable",
                          f"SQL Injection vulnerability found in form: {form['action']}",
                          {"form_details": form, "payload": payload},
                      )
                      return  # Stop testing this form after finding one vulnerability
                  else:
                        self.log_result(
                        "SQL Injection",
                        "Safe",
                        f"SQL Injection test on form {form['action']} with payload: {payload} was safe",
                    )
        self.log_result("SQL Injection", "Safe", f"No SQL Injection vulnerabilities found in {url}")

    def test_xss(self, url, html_content=None):
        """
        Performs Cross-Site Scripting (XSS) testing on a given URL and its forms.

        Args:
            url (str): The URL to test.
            html_content (str, optional): html content, if already fetched.
        """
        self.log_result("XSS", "Skipped", "Starting XSS test...")
        if html_content is None:
          html_content = self.get_page_content(url)
        if html_content is None:
            self.log_result("XSS", "Error", "Failed to retrieve page content.")
            return

        forms = self.extract_forms(html_content, url)
        if not forms:
            self.log_result("XSS", "Safe", "No forms found on the page.")

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'';!--\"<XSS>=&{()}",
        ]

        for form in forms:
            for payload in xss_payloads:
                data = {}
                for input_field in form["inputs"]:
                    if input_field["type"] != "submit" and input_field["name"]:
                        data[input_field["name"]] = payload
                response_content = self.get_page_content(form["action"], form['method'], data)
                if response_content:
                  if payload in response_content:
                      self.log_result(
                          "XSS",
                          "Vulnerable",
                          f"XSS vulnerability found in form: {form['action']}",
                          {"form_details": form, "payload": payload},
                      )
                      return  # Stop testing this form after finding one vulnerability
                  else:
                        self.log_result(
                            "XSS",
                            "Safe",
                            f"XSS test on form {form['action']} with payload: {payload} was safe",
                        )
        self.log_result("XSS", "Safe", f"No XSS vulnerabilities found in {url}")

    def test_csrf(self, url, html_content=None):
        """
        Performs Cross-Site Request Forgery (CSRF) testing on a given URL and its forms.

        Args:
            url (str): The URL to test.
            html_content(str, optional): html content, if already fetched.
        """
        self.log_result("CSRF", "Skipped", "Starting CSRF test...")
        if html_content is None:
          html_content = self.get_page_content(url)
        if html_content is None:
            self.log_result("CSRF", "Error", "Failed to retrieve page content.")
            return
        forms = self.extract_forms(html_content, url)
        if not forms:
            self.log_result("CSRF", "Safe", "No forms found on the page.")
            return

        csrf_token_names = ["csrf_token", "CSRFToken", "authenticity_token", "csrf"]  # Common CSRF token names

        for form in forms:
            csrf_token_present = False
            for input_field in form["inputs"]:
                if input_field["name"] in csrf_token_names:
                    csrf_token_present = True
                    break
            if not csrf_token_present and form['method'] == 'POST':
                self.log_result(
                    "CSRF",
                    "Vulnerable",
                    f"CSRF vulnerability found in form: {form['action']} (No CSRF token found)",
                    {"form_details": form},
                )
                return
            else:
                self.log_result("CSRF", "Safe", f"CSRF token found in form: {form['action']}")

        self.log_result("CSRF", "Safe", f"No CSRF vulnerabilities found in {url}")

    def test_directory_traversal(self, url):
        """
        Performs Directory Traversal testing on a given URL.

        Args:
            url (str): The URL to test.
        """
        self.log_result("Directory Traversal", "Skipped", "Starting Directory Traversal test...")
        traversal_paths = [
            "../",
            "..\\",
            "../../",
            "..\\..\\",
            "../../../",
            "..\\..\\..\\",
            "/etc/passwd",  # Check for sensitive file access (Linux)
            "C:\\Windows\\win.ini",  # Check for sensitive file access (Windows)
        ]

        for path in traversal_paths:
            test_url = urllib.parse.urljoin(url, path)
            response_content = self.get_page_content(test_url)
            if response_content:
                if "root:" in response_content or "Windows" in response_content:
                    self.log_result(
                        "Directory Traversal",
                        "Vulnerable",
                        f"Directory Traversal vulnerability found.  Accessed: {test_url}",
                        {"path": path},
                    )
                    return
                else:
                    self.log_result(
                        "Directory Traversal",
                        "Safe",
                        f"Directory Traversal test with path: {path} was safe",
                    )
        self.log_result("Directory Traversal", "Safe", f"No Directory Traversal vulnerabilities found in {url}")

    def test_command_injection(self, url, html_content=None):
        """
        Performs Command Injection testing on a given URL and its forms.

        Args:
            url (str): The URL to test.
            html_content (str, optional): html content, if already fetched
        """
        self.log_result("Command Injection", "Skipped", "Starting Command Injection test...")

        if html_content is None:
          html_content = self.get_page_content(url)
        if html_content is None:
            self.log_result("Command Injection", "Error", "Failed to retrieve page content.")
            return

        forms = self.extract_forms(html_content, url)
        if not forms:
            self.log_result("Command Injection", "Safe", "No forms found on the page.")
            return

        injection_payloads = [
            "; ls -la",  # Unix command
            "; dir",  # Windows command
            "| ls -la",
            "| dir",
            "$(ls -la)",  # Command substitution
            "$(dir)",
            "`ls -la`",  # Backticks
            "`dir`",
        ]

        for form in forms:
            for payload in injection_payloads:
                data = {}
                for input_field in form["inputs"]:
                    if input_field["type"] != "submit" and input_field["name"]:
                        data[input_field["name"]] = payload
                response_content = self.get_page_content(form["action"], form['method'], data)
                if response_content:
                  if "total " in response_content.lower() or "<dir>" in response_content.lower():
                      self.log_result(
                          "Command Injection",
                          "Vulnerable",
                          f"Command Injection vulnerability found in form: {form['action']}",
                          {"form_details": form, "payload": payload},
                      )
                      return
                  else:
                        self.log_result(
                            "Command Injection",
                            "Safe",
                            f"Command Injection test on form {form['action']} with payload: {payload} was safe",
                        )
        self.log_result("Command Injection", "Safe", f"No Command Injection vulnerabilities found in {url}")

    def test_file_upload_exploits(self, url, html_content=None):
        """
        Performs File Upload Exploits testing on a given URL and its forms.

        Args:
            url (str): The URL to test.
            html_content (str, optional): html content to use
        """
        self.log_result("File Upload Exploits", "Skipped", "Starting File Upload Exploits test...")
        if html_content is None:
          html_content = self.get_page_content(url)
        if html_content is None:
            self.log_result("File Upload Exploits", "Error", "Failed to retrieve page content.")
            return

        forms = self.extract_forms(html_content, url)
        if not forms:
            self.log_result("File Upload Exploits", "Safe", "No forms found on the page.")
            return

        # Define file upload payloads
        file_payloads = [
            ("test.txt", b"This is a test file."),  # Safe file
            ("test.php", b"<?php echo 'Hello, world!'; ?>"),  # Potentially dangerous PHP
            ("test.html", b"<script>alert('XSS')</script>"),  # HTML with script
            ("test.jpg.php", b"<?php echo 'Hello, world!'; ?>"), # Double extension
            ("test.phtml", b"<?php echo 'Hello, world!'; ?>"),
        ]

        for form in forms:
            for input_field in form["inputs"]:
                if input_field["type"] == "file" and input_field["name"]:
                    for filename, file_content in file_payloads:
                        files = {input_field["name"]: (filename, file_content)}
                        response_content = self.get_page_content(form["action"], form['method'], files=files)
                        if response_content:
                            if "error" not in response_content.lower():
                                self.log_result(
                                    "File Upload Exploits",
                                    "Vulnerable",
                                    f"File Upload vulnerability found in form: {form['action']}.  Uploaded: {filename}",
                                    {"form_details": form, "filename": filename},
                                )
                                return
                            else:
                                self.log_result(
                                    "File Upload Exploits",
                                    "Safe",
                                     f"File Upload test on form: {form['action']}.  Uploaded: {filename} was rejected",
                                )
        self.log_result("File Upload Exploits", "Safe", f"No File Upload Exploits vulnerabilities found in {url}")

    def test_login_brute_force(self, url, username_list, password_list, html_content=None):
        """
        Performs a login brute-force attack on a given URL.

        Args:
            url (str): The URL of the login page.
            username_list (list): A list of usernames to try.
            password_list (list): A list of passwords to try.
            html_content (str, optional): html content, if already fetched.
        """
        self.log_result("Login Brute Force", "Skipped", "Starting Login Brute Force test...")
        if html_content is None:
          html_content = self.get_page_content(url)

        if html_content is None:
            self.log_result("Login Brute Force", "Error", "Failed to retrieve login page content.")
            return

        forms = self.extract_forms(html_content, url)
        if not forms:
            self.log_result("Login Brute Force", "Safe", "No forms found on the page.")
            return

        login_form = None
        for form in forms:
            # Basic heuristics to identify login form.  Improve as needed.
            if any(
                "username" in input_field["name"].lower() or "login" in input_field["name"].lower()
                for input_field in form["inputs"]
            ) and any("password" in input_field["name"].lower() for input_field in form["inputs"]):
                login_form = form
                break

        if not login_form:
            self.log_result("Login Brute Force", "Safe", "Could not identify a login form.")
            return

        username_field = None
        password_field = None
        for input_field in login_form["inputs"]:
            if "username" in input_field["name"].lower() or "login" in input_field["name"].lower():
                username_field = input_field["name"]
            if "password" in input_field["name"].lower():
                password_field = input_field["name"]

        if not username_field or not password_field:
            self.log_result("Login Brute Force", "Error", "Could not identify username or password field.")
            return

        for username in username_list:
            for password in password_list:
                data = {username_field: username, password_field: password}
                response_content = self.get_page_content(login_form["action"], login_form['method'], data, allow_redirects=False) # added allow_redirects=False
                if response_content:
                    if "incorrect" not in response_content.lower() and "invalid" not in response_content.lower(): # added lower()
                        self.log_result(
                            "Login Brute Force",
                            "Vulnerable",
                            f"Successful login with username: {username}, password: {password}",
                            {"username": username, "password": password},
                        )
                        return
                    else:
                         self.log_result(
                            "Login Brute Force",
                            "Safe",
                            f"Failed login attempt with username: {username}, password: {password}",
                        )

        self.log_result("Login Brute Force", "Safe", "Login brute force failed for all combinations.")

    def test_port_scan(self, hostname):
        """
        Performs a port scan on a given hostname using socket.

        Args:
            hostname (str): The hostname or IP address to scan.
        """
        self.log_result("Port Scan", "Skipped", "Starting Port Scan test...")
        ports = [21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]  # Common ports
        open_ports = []

        for port in ports:
            try:
                sock = socket.create_connection((hostname, port), timeout=3)
                sock.close()
                open_ports.append(port)
                self.log_result(
                    "Port Scan", "Vulnerable", f"Port {port} is open", {"port": port}
                )
            except (socket.timeout, ConnectionRefusedError):
                self.log_result("Port Scan", "Safe", f"Port {port} is closed", {"port": port})
            except Exception as e:
                self.logger.error(f"Error scanning port {port}: {e}")
                self.log_result("Port Scan", "Error", f"Error scanning port {port}: {e}", {"port": port})

        if open_ports:
            self.log_result(
                "Port Scan",
                "Vulnerable",
                f"Open ports found: {open_ports}",
                {"open_ports": open_ports},
            )
        else:
            self.log_result("Port Scan", "Safe", "No open ports found.")

    def test_unauthorized_access(self, url):
        """
        Attempts to gain unauthorized access to sensitive directories and files.

        Args:
            url (str): The base URL of the website.
        """
        self.log_result("Unauthorized Access", "Skipped", "Starting Unauthorized Access test...")
        sensitive_paths = [
            "/admin/",
            "/administrator/",
            "/config/",
            "/.git/",
            "/wp-admin/",  # WordPress admin
            "/server-status",  # Apache server status
            "/phpinfo.php",
            "/.env", #check for .env file
        ]

        for path in sensitive_paths:
            test_url = urllib.parse.urljoin(url, path)
            response_content = self.get_page_content(test_url)
            if response_content:
                if response_content and response_content.status_code != 404:
                    self.log_result(
                        "Unauthorized Access",
                        "Vulnerable",
                        f"Potentially sensitive resource accessible: {test_url}",
                        {"path": path},
                    )
                else:
                    self.log_result(
                        "Unauthorized Access",
                        "Safe",
                        f"Unauthorized Access test with path: {path} was safe",
                    )
        self.log_result("Unauthorized Access", "Safe", "No Unauthorized Access vulnerabilities found")

    def crawl_website(self, url, max_depth=3):
        """
        Crawls the website to discover endpoints, forms, and input fields.

        Args:
            url (str): The starting URL for the crawl.
            max_depth (int, optional): The maximum depth to crawl. Defaults to 3.
        """
        self.log_result("Website Crawl", "Skipped", f"Starting website crawl at {url} with max depth {max_depth}...")
        visited_urls = set()
        urls_to_visit = [(url, 0)]  # (URL, depth)
        all_endpoints = set()
        all_forms = []

        while urls_to_visit:
            current_url, depth = urls_to_visit.pop(0)

            if depth > max_depth or current_url in visited_urls:
                continue

            visited_urls.add(current_url)
            self.logger.info(f"Crawling: {current_url} (Depth: {depth})")
            page_content = self.get_page_content(current_url)
            if not page_content:
                continue

            all_endpoints.add(current_url)
            forms = self.extract_forms(page_content, current_url)
            all_forms.extend(forms)

            # Extract links for further crawling
            try:
                soup = BeautifulSoup(page_content, "html.parser")
                links = soup.find_all("a")
                for link in links:
                    href = link.get("href")
                    if href:
                        absolute_url = urllib.parse.urljoin(current_url, href)
                        if absolute_url.startswith(self.target_url):  # Stay within the target website
                            urls_to_visit.append((absolute_url, depth + 1))
            except Exception as e:
                self.logger.error(f"Error extracting links from {current_url}: {e}")
                self.log_result("Website Crawl", "Error", f"Error extracting links: {e}", {"url": current_url})

        self.log_result(
            "Website Crawl",
            "Success",
            f"Crawled {len(visited_urls)} pages. Found {len(all_endpoints)} endpoints and {len(all_forms)} forms.",
            {"visited_urls": list(visited_urls), "endpoints": list(all_endpoints), "forms": all_forms},
        )
        return list(visited_urls), all_forms

    def run_all_tests(self, username_list=None, password_list=None, crawl=True):
        """
        Runs all defined security tests.

        Args:
            username_list (list, optional): A list of usernames for brute-force attack. Defaults to None.
            password_list (list, optional): A list of passwords for brute-force attack. Defaults to None.
            crawl (bool): Whether to crawl the website before testing.
        """
        start_time = time.time()
        self.report["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if crawl:
            crawled_urls, crawled_forms = self.crawl_website(self.target_url)
        else:
            crawled_urls = [self.target_url]  # If not crawling, just test the target URL
            crawled_forms = []
            html_content = self.get_page_content(self.target_url) #fetch

        # Use ThreadPoolExecutor to run tests concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
            futures = []
            for url in crawled_urls:
                if crawl:
                  html_content = self.get_page_content(url)
                else:
                   html_content = self.get_page_content(url) #make sure html_content is fetched
                futures.append(executor.submit(self.test_sqli, url, html_content))
                futures.append(executor.submit(self.test_xss, url, html_content))
                futures.append(executor.submit(self.test_csrf, url, html_content))
                futures.append(executor.submit(self.test_directory_traversal, url))
                futures.append(executor.submit(self.test_command_injection, url, html_content))
                futures.append(executor.submit(self.test_file_upload_exploits, url, html_content))
                if username_list and password_list:
                    futures.append(executor.submit(self.test_login_brute_force, self.target_url, username_list, password_list, html_content))

            # Wait for all tests to complete
            concurrent.futures.wait(futures)

        if not crawl:
            if username_list and password_list:
                self.test_login_brute_force(self.target_url, username_list, password_list) #run login brute force if not crawling

        self.test_port_scan(urllib.parse.urlparse(self.target_url).netloc)  # Scan the hostname

        end_time = time.time()
        self.report["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report["duration"] = end_time - start_time
        self.generate_report()

    def generate_report(self):
        """
        Generates a report of the test results in a simple text format.
        """
        report_filename = f"{self.report_dir}/security_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(report_filename, "w") as f:
                f.write(f"Security Test Report for {self.target_url}\n")
                f.write(f"Start Time: {self.report['start_time']}\n")
                f.write(f"End Time: {self.report['end_time']}\n")
                f.write(f"Duration: {self.report['duration']:.2f} seconds\n\n")
                f.write("======================================================================\n")
                f.write("Test Results\n")
                f.write("======================================================================\n")

                for test_name, result in self.report.items():
                    f.write(f"Test: {test_name}\n")
                    f.write(f"Status: {result['status']}\n")
                    f.write(f"Message: {result['message']}\n")
                    if result['data']:
                        f.write(f"Data: {result['data']}\n")
                    f.write("-" * 40 + "\n")
                print(f"Report generated successfully: {report_filename}")
                self.logger.info(f"Report generated: {report_filename}")
        except Exception as e:
            print(f"Error generating report: {e}")
            self.logger.error(f"Error generating report: {e}")
        return report_filename #added return

    def display_report(self):
        """Displays the report on the console"""
        print("======================================================================")
        print(f"Security Test Report for {self.target_url}")
        print(f"Start Time: {self.report['start_time']}")
        print(f"End Time: {self.report['end_time']}")
        print(f"Duration: {self.report['duration']:.2f} seconds")
        print("======================================================================\n")
        print("Test Results\n")
        print("======================================================================\n")
        for test_name, result in self.report.items():
            print(f"Test: {test_name}")
            print(f"Status: {result['status']}")
            print(f"Message: {result['message']}")
            if result['data']:
             print(f"Data: {result['data']}")
            print("-" * 40 + "\n")
        else:
            print("No test results available.")
def main():
    """
    Main function to take user input and run the security tests.
    """
    target_url = input("Enter the target URL (e.g., https://example.com): ")
    crawl_input = input("Crawl the website? (yes/no, default: yes): ").lower() or "yes"
    crawl = crawl_input == "yes"
    username_file = input("Enter path to username list file (optional for brute-force): ")
    password_file = input("Enter path to password list file (optional for brute-force): ")

    username_list = []
    password_list = []
    if username_file and password_file:
        try:
            with open(username_file, "r") as f:
                username_list = [line.strip() for line in f]
            with open(password_file, "r") as f:
                password_list = [line.strip() for line in f]
        except FileNotFoundError:
            print("Error: Username or password file not found. Skipping brute-force test.")
            username_list = []
            password_list = []

    test = SecurityTest(target_url)
    test.run_all_tests(username_list, password_list, crawl)
    test.display_report() #display report on console
    # Save the report to a file
    test.generate_report() #generate report and save to file

if __name__ == "__main__":
    main()
