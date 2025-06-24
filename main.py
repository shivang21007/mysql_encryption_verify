#!/usr/bin/env python3
"""
MySQL Database Encryption Scanner

This script scans all tables in a MySQL database and checks whether they are encrypted.
It supports both table-level encryption (TDE) and column-level encryption checks.
"""

import mysql.connector
import sys
import argparse
from typing import Dict, List, Tuple
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
import os


class MySQLEncryptionScanner:
    def __init__(self, host: str, user: str, password: str, database: str, port: int = 3306):
        """Initialize the scanner with database connection parameters."""
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.port = port
        self.connection = None

    def connect(self) -> bool:
        """Establish connection to MySQL database."""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
                port=self.port,
                autocommit=True
            )
            print(f"✅ Successfully connected to MySQL database: {self.database}")
            return True
        except mysql.connector.Error as err:
            print(f"❌ Error connecting to MySQL: {err}")
            return False

    def disconnect(self):
        """Close the database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("🔌 Database connection closed.")

    def get_all_tables(self) -> List[str]:
        """Get all table names from the database."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]
            cursor.close()
            return tables
        except mysql.connector.Error as err:
            print(f"❌ Error getting tables: {err}")
            return []

    def check_table_encryption_status(self, table_name: str) -> Dict:
        """Check encryption status for a specific table."""
        result = {
            'table_name': table_name,
            'encrypted': False,
            'encryption_type': None,
            'encryption_algorithm': None,
            'encryption_key': None,
            'details': {}
        }

        try:
            cursor = self.connection.cursor(dictionary=True)
            
            # Check table encryption using information_schema
            query = """
            SELECT 
                TABLE_NAME,
                TABLE_SCHEMA,
                CREATE_OPTIONS,
                TABLE_COMMENT
            FROM information_schema.TABLES 
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
            """
            cursor.execute(query, (self.database, table_name))
            table_info = cursor.fetchone()
            
            if table_info:
                result['details']['create_options'] = table_info.get('CREATE_OPTIONS', '')
                result['details']['table_comment'] = table_info.get('TABLE_COMMENT', '')
                
                # Check for encryption in CREATE_OPTIONS
                create_options = table_info.get('CREATE_OPTIONS', '').lower()
                if 'encryption' in create_options or 'encrypted' in create_options:
                    result['encrypted'] = True
                    result['encryption_type'] = 'Table-level encryption'
                    
                    # Try to extract encryption algorithm from CREATE_OPTIONS
                    if 'aes' in create_options:
                        result['encryption_algorithm'] = 'AES'
                    elif 'des' in create_options:
                        result['encryption_algorithm'] = 'DES'
                    elif '3des' in create_options or 'triple des' in create_options:
                        result['encryption_algorithm'] = '3DES'
                    else:
                        result['encryption_algorithm'] = 'AES (default)'
                
                # Check for encryption using SHOW CREATE TABLE
                cursor.execute(f"SHOW CREATE TABLE `{table_name}`")
                create_table_result = cursor.fetchone()
                if create_table_result:
                    create_statement = create_table_result['Create Table']
                    result['details']['create_statement'] = create_statement
                    
                    # Look for encryption keywords in CREATE TABLE statement
                    create_lower = create_statement.lower()
                    if 'encryption' in create_lower or 'encrypted' in create_lower:
                        result['encrypted'] = True
                        if result['encryption_type'] is None:
                            result['encryption_type'] = 'Table-level encryption'
                    
                    # Check for specific encryption algorithms in CREATE STATEMENT
                    if result['encrypted'] and result['encryption_algorithm'] is None:
                        if 'aes' in create_lower:
                            result['encryption_algorithm'] = 'AES'
                        elif 'des' in create_lower:
                            result['encryption_algorithm'] = 'DES'
                        elif '3des' in create_lower or 'triple des' in create_lower:
                            result['encryption_algorithm'] = '3DES'
                        else:
                            result['encryption_algorithm'] = 'AES (default)'

            # Check for column-level encryption
            column_encryption = self.check_column_encryption(cursor, table_name)
            if column_encryption:
                result['encrypted'] = True
                result['encryption_type'] = 'Column-level encryption'
                result['details']['encrypted_columns'] = column_encryption

            cursor.close()
            
        except mysql.connector.Error as err:
            result['error'] = str(err)
            print(f"❌ Error checking table {table_name}: {err}")

        return result

    def check_column_encryption(self, cursor, table_name: str) -> List[Dict]:
        """Check for column-level encryption."""
        encrypted_columns = []
        
        try:
            # Get column information
            query = """
            SELECT 
                COLUMN_NAME,
                DATA_TYPE,
                COLUMN_TYPE,
                COLUMN_COMMENT,
                EXTRA
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
            """
            cursor.execute(query, (self.database, table_name))
            columns = cursor.fetchall()
            
            for column in columns:
                column_info = {
                    'column_name': column['COLUMN_NAME'],
                    'data_type': column['DATA_TYPE'],
                    'column_type': column['COLUMN_TYPE'],
                    'comment': column['COLUMN_COMMENT'],
                    'extra': column['EXTRA']
                }
                
                # Check for encryption indicators in column definition
                column_type_lower = column['COLUMN_TYPE'].lower()
                comment_lower = column['COLUMN_COMMENT'].lower()
                extra_lower = column['EXTRA'].lower()
                
                if ('encrypted' in column_type_lower or 
                    'encrypted' in comment_lower or 
                    'encrypted' in extra_lower):
                    column_info['encrypted'] = True
                    encrypted_columns.append(column_info)
                
                # Check for specific encryption functions or types
                if any(keyword in column_type_lower for keyword in ['aes_encrypt', 'aes_decrypt', 'encrypt', 'decrypt']):
                    column_info['encrypted'] = True
                    encrypted_columns.append(column_info)

        except mysql.connector.Error as err:
            print(f"❌ Error checking column encryption for {table_name}: {err}")

        return encrypted_columns

    def scan_all_tables(self) -> Dict:
        """Scan all tables in the database for encryption."""
        print(f"\n🔍 Scanning database '{self.database}' for encrypted tables...")
        
        tables = self.get_all_tables()
        if not tables:
            print("❌ No tables found in the database.")
            return {}

        print(f"📋 Found {len(tables)} tables to scan.")
        
        results = {
            'host': self.host,
            'database': self.database,
            'total_tables': len(tables),
            'encrypted_tables_count': 0,
            'unencrypted_tables_count': 0,
            'encrypted_tables': [],
            'unencrypted_tables': []
        }

        for i, table_name in enumerate(tables, 1):
            print(f"  [{i}/{len(tables)}] Scanning table: {table_name}")
            table_result = self.check_table_encryption_status(table_name)
            
            if table_result['encrypted']:
                results['encrypted_tables'].append(table_result)
                results['encrypted_tables_count'] += 1
                print(f"    ✅ {table_name} - ENCRYPTED ({table_result['encryption_type']})")
            else:
                results['unencrypted_tables'].append(table_result)
                results['unencrypted_tables_count'] += 1
                print(f"    ❌ {table_name} - NOT ENCRYPTED")

        return results

    def print_summary(self, results: Dict):
        """Print a summary of the encryption scan results."""
        print("\n" + "="*60)
        print(f"🔐 ENCRYPTION SCAN SUMMARY : {self.host}")
        print("="*60)
        print(f"Database: {results['database']}")
        print(f"Total Tables: {results['total_tables']}")
        print(f"Encrypted Tables: {results['encrypted_tables_count']}")
        print(f"Unencrypted Tables: {results['unencrypted_tables_count']}")
        
        if results['encrypted_tables_count'] > 0:
            print(f"\n📊 Encryption Rate: {(results['encrypted_tables_count']/results['total_tables'])*100:.1f}%")
        
        print("\n📋 DETAILED RESULTS:")
        print("-" * 60)
        
        # Print encrypted tables first
        for table in results['encrypted_tables']:
            status = "🔒 ENCRYPTED"
            print(f"{table['table_name']:<30} {status}")
            print(f"  └─ Type: {table['encryption_type']}")
            if table['encryption_algorithm']:
                print(f"  └─ Algorithm: {table['encryption_algorithm']}")
            if 'encrypted_columns' in table['details']:
                print(f"  └─ Encrypted Columns: {len(table['details']['encrypted_columns'])}")
        
        # Print unencrypted tables
        for table in results['unencrypted_tables']:
            status = "🔓 NOT ENCRYPTED"
            print(f"{table['table_name']:<30} {status}")

    def save_results(self, results: Dict, filename: str = None):
        """Save results to a JSON file."""
        if not filename:
            filename = f"encryption_scan_{self.database}_{results['total_tables']}_tables.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")


class EmailReporter:
    """Email reporting functionality for MySQL encryption scan results."""
    
    def __init__(self, smtp_server: str = "smtp.gmail.com", smtp_port: int = 587):
        """Initialize email reporter with SMTP settings."""
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = None
        self.sender_password = None
        
    def configure_sender(self, email: str, password: str):
        """Configure sender email and password."""
        self.sender_email = email
        self.sender_password = password
        
    def create_email_body(self, results: Dict) -> str:
        """Create HTML email body from scan results."""
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                .table th, .table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                .table th {{ background-color: #34495e; color: white; }}
                .encrypted {{ background-color: #d5f4e6; color: #27ae60; }}
                .not-encrypted {{ background-color: #fadbd8; color: #e74c3c; }}
                .status-encrypted {{ color: #27ae60; font-weight: bold; }}
                .status-not-encrypted {{ color: #e74c3c; font-weight: bold; }}
                .footer {{ background-color: #95a5a6; color: white; padding: 15px; border-radius: 5px; margin-top: 20px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 MySQL Database Encryption Scan Report : ({results['host']})</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>📊 Scan Summary</h2>
                <p><strong>Database:</strong> {results['database']}</p>
                <p><strong>Total Tables:</strong> {results['total_tables']}</p>
                <p><strong>Encrypted Tables:</strong> {results['encrypted_tables_count']}</p>
                <p><strong>Unencrypted Tables:</strong> {results['unencrypted_tables_count']}</p>
                <p><strong>Encryption Rate:</strong> {(results['encrypted_tables_count']/results['total_tables'])*100:.1f}%</p>
            </div>
            
            <h2>📋 Detailed Results</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Table Name</th>
                        <th>Status</th>
                        <th>Encryption Type</th>
                        <th>Algorithm</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Add encrypted tables first
        for table in results['encrypted_tables']:
            status_class = "status-encrypted"
            row_class = "encrypted"
            status_text = "🔒 ENCRYPTED"
            
            html_body += f"""
                    <tr class="{row_class}">
                        <td><strong>{table['table_name']}</strong></td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{table['encryption_type'] or 'N/A'}</td>
                        <td>{table['encryption_algorithm'] or 'N/A'}</td>
                    </tr>
            """
        
        # Add unencrypted tables
        for table in results['unencrypted_tables']:
            status_class = "status-not-encrypted"
            row_class = "not-encrypted"
            status_text = "🔓 NOT ENCRYPTED"
            
            html_body += f"""
                    <tr class="{row_class}">
                        <td><strong>{table['table_name']}</strong></td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{table['encryption_type'] or 'N/A'}</td>
                        <td>{table['encryption_algorithm'] or 'N/A'}</td>
                    </tr>
            """
        
        html_body += """
                </tbody>
            </table>
            
            <div class="footer">
                <p>This report was generated by MySQL Database Encryption Scanner</p>
                <p>For security questions, please contact <a href="mailto:shivang.gupta@octrotalk.com">developer</a></p>
            </div>
        </body>
        </html>
        """
        
        return html_body
        
    def send_email_report(self, results: Dict, recipient_email: str, json_file_path: str = None) -> bool:
        """Send email report with scan results."""
        if not self.sender_email or not self.sender_password:
            print("❌ Email sender not configured. Please set email and password.")
            return False
            
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = f"🔐 MySQL Encryption Scan Report : ({results['host']}) : ({results['database']}) : ({datetime.now().strftime('%Y-%m-%d')})"
            
            # Create email body
            html_body = self.create_email_body(results)
            msg.attach(MIMEText(html_body, 'html'))
            
            # Attach JSON report if provided
            if json_file_path and os.path.exists(json_file_path):
                with open(json_file_path, 'rb') as f:
                    json_attachment = MIMEApplication(f.read(), _subtype='json')
                    json_attachment.add_header('Content-Disposition', 'attachment', 
                                             filename=os.path.basename(json_file_path))
                    msg.attach(json_attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
                
            print(f"✅ Email report sent successfully to: {recipient_email}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            print("❌ Email authentication failed. Please check your email and password.")
            print("💡 Note: You may need to use an App Password if 2FA is enabled on your Google account.")
            return False
        except smtplib.SMTPException as e:
            print(f"❌ Email sending failed: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error sending email: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='MySQL Database Encryption Scanner')
    parser.add_argument('--host', default='localhost', help='MySQL host (default: localhost)')
    parser.add_argument('--port', type=int, default=3306, help='MySQL port (default: 3306)')
    parser.add_argument('--user', required=True, help='MySQL username')
    parser.add_argument('--password', required=True, help='MySQL password')
    parser.add_argument('--database', required=True, help='Database name to scan')
    parser.add_argument('--output', help='Output JSON file name (optional)')
    
    # Email arguments
    parser.add_argument('--email', help='Send email report to this address')
    parser.add_argument('--email-username', help='Sender email address (Gmail)')
    parser.add_argument('--email-password', help='Sender email password or app password')
    
    args = parser.parse_args()

    # Create scanner instance
    scanner = MySQLEncryptionScanner(
        host=args.host,
        user=args.user,
        password=args.password,
        database=args.database,
        port=args.port
    )

    # Connect to database
    if not scanner.connect():
        sys.exit(1)

    try:
        # Scan all tables
        results = scanner.scan_all_tables()
        
        if results:
            # Print summary
            scanner.print_summary(results)
            
            # Save results if requested
            json_file_path = None
            if args.output:
                scanner.save_results(results, args.output)
                json_file_path = args.output
            else:
                scanner.save_results(results)
                json_file_path = f"encryption_scan_{results['database']}_{results['total_tables']}_tables.json"
            
            # Send email report if requested
            if args.email:
                if not args.email_username or not args.email_password:
                    print("❌ Email sender and password are required for email functionality.")
                    print("Usage: --email-username your_email@gmail.com --email-password your_gmail_app_password")
                    sys.exit(1)
                
                print(f"\n📧 Sending email report to: {args.email}")
                email_reporter = EmailReporter()
                email_reporter.configure_sender(args.email_username, args.email_password)
                
                if email_reporter.send_email_report(results, args.email, json_file_path):
                    print("✅ Email report sent successfully!")
                else:
                    print("❌ Failed to send email report.")
        else:
            print("❌ No results obtained from scan.")
            
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    finally:
        scanner.disconnect()


if __name__ == "__main__":
    main()
