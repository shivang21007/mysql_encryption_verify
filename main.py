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
            'database': self.database,
            'total_tables': len(tables),
            'encrypted_tables': 0,
            'unencrypted_tables': 0,
            'tables': []
        }

        for i, table_name in enumerate(tables, 1):
            print(f"  [{i}/{len(tables)}] Scanning table: {table_name}")
            table_result = self.check_table_encryption_status(table_name)
            results['tables'].append(table_result)
            
            if table_result['encrypted']:
                results['encrypted_tables'] += 1
                print(f"    ✅ {table_name} - ENCRYPTED ({table_result['encryption_type']})")
            else:
                results['unencrypted_tables'] += 1
                print(f"    ❌ {table_name} - NOT ENCRYPTED")

        return results

    def print_summary(self, results: Dict):
        """Print a summary of the encryption scan results."""
        print("\n" + "="*60)
        print("🔐 ENCRYPTION SCAN SUMMARY")
        print("="*60)
        print(f"Database: {results['database']}")
        print(f"Total Tables: {results['total_tables']}")
        print(f"Encrypted Tables: {results['encrypted_tables']}")
        print(f"Unencrypted Tables: {results['unencrypted_tables']}")
        
        if results['encrypted_tables'] > 0:
            print(f"\n📊 Encryption Rate: {(results['encrypted_tables']/results['total_tables'])*100:.1f}%")
        
        print("\n📋 DETAILED RESULTS:")
        print("-" * 60)
        
        for table in results['tables']:
            status = "🔒 ENCRYPTED" if table['encrypted'] else "🔓 NOT ENCRYPTED"
            print(f"{table['table_name']:<30} {status}")
            
            if table['encrypted']:
                print(f"  └─ Type: {table['encryption_type']}")
                if table['encryption_algorithm']:
                    print(f"  └─ Algorithm: {table['encryption_algorithm']}")
                if 'encrypted_columns' in table['details']:
                    print(f"  └─ Encrypted Columns: {len(table['details']['encrypted_columns'])}")

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


def main():
    parser = argparse.ArgumentParser(description='MySQL Database Encryption Scanner')
    parser.add_argument('--host', default='localhost', help='MySQL host (default: localhost)')
    parser.add_argument('--port', type=int, default=3306, help='MySQL port (default: 3306)')
    parser.add_argument('--user', required=True, help='MySQL username')
    parser.add_argument('--password', required=True, help='MySQL password')
    parser.add_argument('--database', required=True, help='Database name to scan')
    parser.add_argument('--output', help='Output JSON file name (optional)')
    
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
            if args.output:
                scanner.save_results(results, args.output)
            else:
                scanner.save_results(results)
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
