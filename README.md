# MySQL Database Encryption Scanner

A comprehensive Python script to scan all tables in a MySQL database and check whether they are encrypted or not. This tool supports both table-level encryption (TDE) and column-level encryption detection.

## Features

- 🔍 **Complete Database Scan**: Scans all tables in the specified database
- 🔐 **Multiple Encryption Types**: Detects table-level and column-level encryption
- 📊 **Detailed Reporting**: Provides comprehensive encryption status reports
- 💾 **JSON Export**: Saves results to JSON files for further analysis
- 🎯 **Algorithm Detection**: Identifies encryption algorithms (AES, DES, 3DES)
- 📋 **Progress Tracking**: Shows real-time scanning progress
- 

## Installation

1. **Clone or download the script files**
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
python main.py --user your_username --password your_password --database your_database
```

### Advanced Usage

```bash
python main.py \
  --host localhost \
  --port 3306 \
  --user your_username \
  --password your_password \
  --database your_database \
  --output encryption_report.json
```

### Command Line Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--host` | MySQL server host | localhost | No |
| `--port` | MySQL server port | 3306 | No |
| `--user` | MySQL username | - | **Yes** |
| `--password` | MySQL password | - | **Yes** |
| `--database` | Database name to scan | - | **Yes** |
| `--output` | Output JSON file name | auto-generated | No |
| `--email` | Send email report to this address | - | No |
| `--email-username` | Sender email address (Gmail) | - | No |
| `--email-password` | Sender email password or app password | - | No |

## Email Reporting Feature

The scanner now supports sending encrypted HTML email reports with JSON attachments.

### Email Setup

1. **Gmail Configuration**:
   - Enable 2-Factor Authentication on your Gmail account
   - Generate an App Password:
     - Go to Google Account Settings → Security
     - Under "2-Step Verification", click "App passwords"
     - Generate a new app password for "Mail"
   - Use this app password instead of your regular Gmail password

2. **Email Usage**:
   ```bash
   python main.py \
     --user your_username \
     --password your_password \
     --database your_database \
     --email recipient@example.com \
     --email-username your_email@gmail.com \
     --email-password your_app_password
   ```

### Email Report Features

- **HTML Email Body**: Beautiful, formatted report with encryption summary
- **JSON Attachment**: Complete scan results attached as JSON file
- **Color-coded Results**: Green for encrypted, red for unencrypted tables
- **Professional Styling**: Clean, modern email design
- **Security Summary**: Encryption rate and detailed statistics

### Email Report Example

The email includes:
- 📊 **Scan Summary**: Database name, total tables, encryption statistics
- 📋 **Detailed Table Results**: Status, encryption type, and algorithm for each table
- 📎 **JSON Attachment**: Complete scan data for further analysis
- 🎨 **Professional Formatting**: HTML email with color-coded results

## What the Script Checks

### Table-Level Encryption
- **CREATE_OPTIONS**: Checks for encryption flags in table creation options
- **SHOW CREATE TABLE**: Analyzes the complete table creation statement
- **Information Schema**: Queries `information_schema.TABLES` for encryption metadata

### Column-Level Encryption
- **Column Definitions**: Checks for encryption keywords in column types
- **Column Comments**: Looks for encryption indicators in column comments
- **Extra Attributes**: Examines column extra attributes for encryption flags
- **Encryption Functions**: Detects AES_ENCRYPT, AES_DECRYPT, ENCRYPT, DECRYPT usage

### Encryption Algorithms Detected
- **AES** (Advanced Encryption Standard)
- **DES** (Data Encryption Standard)
- **3DES** (Triple DES)

## Output

### Console Output
The script provides real-time feedback during scanning:

```
✅ Successfully connected to MySQL database: my_database

🔍 Scanning database 'my_database' for encrypted tables...
📋 Found 5 tables to scan.
  [1/5] Scanning table: users
    ❌ users - NOT ENCRYPTED
  [2/5] Scanning table: sensitive_data
    ✅ sensitive_data - ENCRYPTED (Table-level encryption)
  [3/5] Scanning table: logs
    ❌ logs - NOT ENCRYPTED
  [4/5] Scanning table: encrypted_columns
    ✅ encrypted_columns - ENCRYPTED (Column-level encryption)
  [5/5] Scanning table: config
    ❌ config - NOT ENCRYPTED

============================================================
🔐 ENCRYPTION SCAN SUMMARY
============================================================
Database: my_database
Total Tables: 5
Encrypted Tables: 2
Unencrypted Tables: 3

📊 Encryption Rate: 40.0%

📋 DETAILED RESULTS:
------------------------------------------------------------
users                           🔓 NOT ENCRYPTED
sensitive_data                  🔒 ENCRYPTED
  └─ Type: Table-level encryption
  └─ Algorithm: AES
encrypted_columns               🔒 ENCRYPTED
  └─ Type: Column-level encryption
  └─ Encrypted Columns: 2
logs                           🔓 NOT ENCRYPTED
config                         🔓 NOT ENCRYPTED

💾 Results saved to: encryption_scan_my_database_5_tables.json
```

### JSON Output
The script generates a detailed JSON report:

```json
{
  "database": "my_database",
  "total_tables": 5,
  "encrypted_tables": 2,
  "unencrypted_tables": 3,
  "tables": [
    {
      "table_name": "sensitive_data",
      "encrypted": true,
      "encryption_type": "Table-level encryption",
      "encryption_algorithm": "AES",
      "encryption_key": null,
      "details": {
        "create_options": "encrypted=YES",
        "table_comment": "",
        "create_statement": "CREATE TABLE `sensitive_data` (...)"
      }
    },
    {
      "table_name": "encrypted_columns",
      "encrypted": true,
      "encryption_type": "Column-level encryption",
      "encryption_algorithm": null,
      "encryption_key": null,
      "details": {
        "encrypted_columns": [
          {
            "column_name": "password",
            "data_type": "varchar",
            "column_type": "varchar(255)",
            "comment": "encrypted password field",
            "extra": "",
            "encrypted": true
          }
        ]
      }
    }
  ]
}
```

## Security Considerations

⚠️ **Important Security Notes**:

1. **Credentials**: Never hardcode database credentials in the script
2. **Network Security**: Use SSL/TLS connections for production databases
3. **Permissions**: Ensure the MySQL user has appropriate read permissions
4. **Output Files**: Secure the generated JSON files as they may contain sensitive metadata

## Troubleshooting

### Common Issues

1. **Connection Errors**:
   - Verify MySQL server is running
   - Check host, port, and credentials
   - Ensure network connectivity

2. **Permission Errors**:
   - MySQL user needs `SELECT` permission on `information_schema`
   - MySQL user needs `SHOW` permission on the target database

3. **No Tables Found**:
   - Verify the database name is correct
   - Check if the database contains any tables
   - Ensure the user has access to the database

### Error Messages

- `❌ Error connecting to MySQL`: Check connection parameters
- `❌ Error getting tables`: Verify database permissions
- `❌ Error checking table`: Individual table access issues

## Examples

### Example 1: Local Database Scan
```bash
python main.py --user root --password mypassword --database testdb
```

### Example 2: Remote Database with Custom Output
```bash
python main.py \
  --host 192.168.1.100 \
  --port 3306 \
  --user dbuser \
  --password dbpass \
  --database production_db \
  --output encryption_report.json
```

### Example 3: Using Environment Variables (Recommended)
```bash
export MYSQL_USER=myuser
export MYSQL_PASSWORD=mypassword
export MYSQL_DATABASE=mydb

python main.py \
  --user $MYSQL_USER \
  --password $MYSQL_PASSWORD \
  --database $MYSQL_DATABASE
```

### Example 4: Email Report with JSON Attachment
```bash
python main.py \
  --user dbuser \
  --password dbpass \
  --database production_db \
  --output encryption_report.json \
  --email admin@company.com \
  --email-username scanner@gmail.com \
  --email-password your_gmail_app_password
```

### Example 5: Complete Email Report (Auto-generated JSON)
```bash
python main.py \
  --host 192.168.1.100 \
  --port 3306 \
  --user dbuser \
  --password dbpass \
  --database security_db \
  --output encryption_report.json \
  --email security-team@company.com \
  --email-username scanner@gmail.com \
  --email-password your_app_password
```

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## License

This script is provided as-is for educational and security assessment purposes. 