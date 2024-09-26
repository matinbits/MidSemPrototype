import streamlit as st
from scanner1 import WebVulnerabilityScanner  # Ensure your scanner code is in a file named scanner.py
import base64
import time
import altair as alt
import pandas as pd
import os

# Function to set a custom background image
def set_background(image_path):
    if os.path.exists(image_path):
        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode()
        st.markdown(
            f"""
            <style>
            .stApp {{
                background-image: url(data:image/{"jpg"};base64,{encoded_string});
                background-size: cover;
                color: white;
            }}
            </style>
            """,
            unsafe_allow_html=True
        )
    else:
        st.warning("Background image not found. Using default background.")

# Function to add a custom favicon
def add_custom_favicon(icon_path):
    if os.path.exists(icon_path):
        with open(icon_path, "rb") as icon_file:
            encoded_icon = base64.b64encode(icon_file.read()).decode()
        st.markdown(
            f"""
            <link rel="icon" href="data:image/x-icon;base64,{encoded_icon}">
            """,
            unsafe_allow_html=True
        )
    else:
        st.warning("Favicon not found. Using default icon.")

# Function to set custom button styles with animations
def set_button_style():
    st.markdown(
        """
        <style>
        .stButton > button {
            color: white;
            background-color: #FF4B4B;
            border-radius: 5px;
            padding: 10px 20px;
            font-size: 16px;
            transition: background-color 0.3s ease, transform 0.3s ease;
        }
        .stButton > button:hover {
            background-color: #cc0000;
            transform: scale(1.05);
        }
        .st-progress {
            color: #FF4B4B;
            font-size: 16px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

def main():
    # Set the custom background image and favicon
    set_background("background.jpg")  # Ensure you have a background.jpg file in your directory
    add_custom_favicon("favicon.ico")  # Ensure you have a favicon.ico file in your directory
    set_button_style()  # Apply custom button styles

    # Highlighted and centered title
    st.markdown(
        """
        <h1 style="text-align: center; color: #FF4B4B; font-weight: bold;">
            AutoPent
        </h1>
        <h3 style="text-align: center; color: #FFFFFF;">
            A comprehensive web application vulnerability scanner
        </h3>
        """,
        unsafe_allow_html=True
    )

    st.write("<p style='text-align: center; color: #FFFFFF;'>AutoPent is a powerful web vulnerability scanner designed to detect SQL Injection, XSS, RCE, Local File Inclusion (LFI), and Open Redirect vulnerabilities.</p>", unsafe_allow_html=True)

    # Create a container for input fields
    with st.container():
        base_url = st.text_input("Enter the URL to scan:", placeholder="http://example.com")
        result_file = st.text_input("Enter the name for the result file (without extension):", placeholder="vulnerability_report")

        # Input validation
        if not base_url or not result_file:
            st.error("Please enter both a valid URL and a result file name.")
            return

        # Arrange payload fields in a two-column layout
        col1, col2 = st.columns(2)

        default_sql_payloads = ', '.join(WebVulnerabilityScanner(base_url).sql_payloads)

        with col1:
            sql_payloads = [payload.strip() for payload in st.text_area("SQL Injection Payloads (comma-separated):", default_sql_payloads).split(',')]

        # Checkbox section to select vulnerabilities to scan
        st.write("### Select Vulnerabilities to Scan", unsafe_allow_html=True)
        sql_check = st.checkbox("SQL Injection", value=True)
    # Styled scan button
    scan_button = st.button("Start Scan", key="start_scan", help="Click to start scanning the website with the selected options.")

    if scan_button:
        st.write(f"Scanning {base_url}...")

        # Display a progress bar with initial 0% progress
        progress_bar = st.progress(0)
        try:
            # Create scanner object and run the scan
            scanner = WebVulnerabilityScanner(
                base_url, sql_payloads, 
            )
            scanner.crawl(base_url)

            # Display the number of internal URLs found
            st.write(f"Internal URLs found: {len(scanner.internal_urls)}")

            total_urls = len(scanner.internal_urls)
            if total_urls == 0:
                st.warning("No internal URLs found during the crawl. Scanning will not proceed.")
                return

            # Normalizing progress step to the [0.0, 1.0] range
            progress_step = 1.0 / total_urls

            for idx, url in enumerate(scanner.internal_urls):
                # Run tests on the URL
                if sql_check:
                    scanner.test_sql_injection(url)
                               
                # Update the progress bar with normalized value
                progress_bar.progress((idx + 1) * progress_step)

            # Generate and display results
            vulnerabilities_df = pd.DataFrame({
                'Vulnerability Type': ['SQL Injection'],
                'Count': [
                    len(scanner.vulnerabilities['SQL Injection']),
                    
                ]
            })

            bar_chart = alt.Chart(vulnerabilities_df).mark_bar(color='#FF4B4B').encode(
                x='Vulnerability Type',
                y='Count'
            )

            st.altair_chart(bar_chart, use_container_width=True)

            st.write("### Detailed Vulnerability Results")
            if any(scanner.vulnerabilities.values()):
                for vuln_type, urls in scanner.vulnerabilities.items():
                    if urls:
                        st.write(f"**{vuln_type}**")
                        for url in urls:
                            st.write(f"- {url}")
            else:
                st.write("No vulnerabilities found.")

            # Save and display report
            report_filename = f"{result_file}.pdf"
            scanner.generate_pdf_report(report_filename)

            st.success(f"Scan completed. Report saved as {report_filename}.")
            with open(f"Reports/{report_filename}", "rb") as file:
                st.download_button(label="Download Report", data=file.read(), file_name=report_filename, mime='application/pdf')
        except Exception as e:
            st.error(f"An error occurred during the scan: {str(e)}")

if __name__ == "__main__":
    main()
