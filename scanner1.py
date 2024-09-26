import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fpdf import FPDF, HTMLMixin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import logging
import re
import os
import chardet  # For automatic encoding detection

# Create folders for logs and reports if they don't exist
os.makedirs('logs', exist_ok=True)
os.makedirs('Reports', exist_ok=True)

# Configure logging with dynamic log file naming
log_filename = f'logs/scanner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
logging.basicConfig(filename=log_filename, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class PDF(FPDF, HTMLMixin):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Web Vulnerability Scan Report', 0, 1, 'C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

class WebVulnerabilityScanner:
    def __init__(self, base_url, sql_payloads=None, xss_payloads=None, rce_payloads=None, lfi_payloads=None, redirect_payloads=None):
        self.base_url = base_url
        self.internal_urls = set()
        self.visited_urls = set()
        self.vulnerabilities = {'SQL Injection': [], 'XSS': [], 'RCE': [], 'LFI': [], 'Open Redirect': []}

        # Default payloads if none are provided
        self.sql_payloads = sql_payloads or [
            "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR 1=1#", "' OR '1'='1'#", 
            "' OR '1'='1' -- -", "' OR '1'='1' AND '1'='1", "' OR '1'='1' OR '1'='1'", "' OR '1'='1' OR 1=1#", "' OR 1=1 --"
        ]
       
    def detect_encoding(self, content):
        """Detect encoding using chardet and return the decoded content."""
        result = chardet.detect(content)
        encoding = result['encoding'] or 'utf-8'  # Fallback to 'utf-8' if detection fails
        logging.info(f"Detected encoding: {encoding}")
        return content.decode(encoding, errors='replace')


    def crawl(self, url):
        """Crawl the website to find all internal URLs."""
        try:
            response = requests.get(url)
            response.raise_for_status()

            # Detect encoding and decode content
            content = self.detect_encoding(response.content)
            soup = BeautifulSoup(content, "lxml")

            # Find all links and form actions
            for link in soup.find_all(["a", "link", "script", "img", "iframe", "form"]):
                href = link.get("href")
                src = link.get("src")
                action = link.get("action")

                if href:
                    full_url = urljoin(self.base_url, href)
                elif src:
                    full_url = urljoin(self.base_url, src)
                elif action:
                    full_url = urljoin(self.base_url, action)
                else:
                    continue

                # Parse URL and ensure it's internal
                parsed_url = urlparse(full_url)
                if self.base_url in full_url and full_url not in self.visited_urls:
                    if full_url not in self.internal_urls:
                        self.internal_urls.add(full_url)
                        self.crawl(full_url)  # Recursive crawl

                self.visited_urls.add(full_url)

        except requests.exceptions.HTTPError as http_err:
            logging.error(f"HTTP error occurred while crawling {url}: {http_err}")
        except requests.exceptions.ConnectionError as conn_err:
            logging.error(f"Connection error occurred while crawling {url}: {conn_err}")
        except requests.exceptions.Timeout as timeout_err:
            logging.error(f"Timeout error occurred while crawling {url}: {timeout_err}")
        except requests.exceptions.RequestException as req_err:
            logging.error(f"An error occurred while crawling {url}: {req_err}")

    def test_sql_injection(self, url):
        """Test for SQL injection vulnerability."""
        for payload in self.sql_payloads:
            try:
                response = requests.get(url, params={"id": payload})
                response.raise_for_status()
                content = self.detect_encoding(response.content)
                if re.search(r'error.*sql', content, re.IGNORECASE) or "mysql" in content.lower():
                    self.vulnerabilities['SQL Injection'].append(url)
                    break
            except requests.exceptions.RequestException as e:
                logging.error(f"Error testing SQL injection on {url}: {e}")

   

    def scan(self, sql_check=True, xss_check=True, rce_check=True, lfi_check=True, redirect_check=True):
        """Scan all internal URLs for vulnerabilities based on user selections."""
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for url in self.internal_urls:
                if sql_check:
                    futures.append(executor.submit(self.test_sql_injection, url))
            

            for future in futures:
                future.result()  # Wait for all tasks to complete

    def generate_pdf_report(self, filename):
        """Generate a professional PDF report of the findings."""
        pdf = PDF()
        pdf.add_page()
        
        # Cover Page
        pdf.set_font("Arial", "B", 24)
        pdf.cell(200, 20, "AutoPent", ln=True, align='C')
        pdf.set_font("Arial", size=16)
        pdf.cell(200, 10, "A Comprehensive Web Application Vulnerability Scanner", ln=True, align='C')
        pdf.ln(20)
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, f"Target URL: {self.base_url}", ln=True, align='C')
        pdf.cell(200, 10, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(20)
        pdf.set_font("Arial", "B", 18)
        pdf.cell(200, 10, "Report Details", ln=True, align='C')
        pdf.ln(10)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, "This report provides a detailed analysis of potential vulnerabilities found during the scan of the specified target URL. The vulnerabilities are categorized by type and include the URLs where each vulnerability was detected.")
        pdf.add_page()

        # Table of Contents
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, "Table of Contents", ln=True, align='L')
        pdf.set_font("Arial", size=12)
        vulnerabilities_set = set(self.vulnerabilities)
        vul_dict = {
            'SQL Injection': [],
        }

        for vulnerability in vulnerabilities_set:
            if 'SQL Injection' in vulnerability:
                vul_dict['SQL Injection'].append(vulnerability)
            
        for vul_type in vul_dict:
            pdf.cell(200, 10, f"{vul_type} - {len(vul_dict[vul_type])} found", ln=True, align='L')

        pdf.add_page()

        # Vulnerabilities Details with Colors
        for vul_type, vul_list in vul_dict.items():
            if vul_list:
                pdf.set_font("Arial", "B", 14)
                color = {
                    'SQL Injection': (255, 0, 0),   # Red
                
                }
                pdf.set_text_color(*color[vul_type])
                pdf.cell(200, 10, f"{vul_type} Vulnerabilities", ln=True, align='L')
                pdf.set_font("Arial", size=12)
                pdf.set_text_color(0, 0, 0)  # Reset to black for the rest of the text
                for vul in vul_list:
                    pdf.multi_cell(0, 10, vul)
                pdf.ln(5)

        report_path = os.path.join("Reports", filename)
        pdf.output(report_path)
        logging.info(f"Report saved to {report_path}")

if __name__ == "__main__":
    base_url = input("Enter the URL to scan: ").strip()
    sql_payloads = input("Enter SQL Injection payloads (comma-separated, leave empty for defaults): ").split(',')

    scanner = WebVulnerabilityScanner(
        base_url, sql_payloads or None,    )
    scanner.crawl(base_url)
    scanner.scan()
    scanner.generate_pdf_report(f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
