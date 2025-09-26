# Cycode RIG (Risk Information Graph) Integration

This repository contains comprehensive tools for fetching vulnerability data from Cycode using their modern RIG GraphQL API and legacy report-based queries.

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Configuration
1. Create `secret.yaml` with your Cycode credentials:
```yaml
cycode:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
```

### Basic Usage
```bash
# Get all open violations (default)
python3 fetch_violations.py

# Get specific violation types (open violations by default)
python3 fetch_violations.py --type SAST
python3 fetch_violations.py --type SCA
python3 fetch_violations.py --type IAC
python3 fetch_violations.py --type LICENSE

# Get violations by status
python3 fetch_violations.py --type SAST --status OPEN
python3 fetch_violations.py --type SAST --status ALL
python3 fetch_violations.py --type SAST --status DISMISSED

# Using RIG reports for bulk exports
python3 fetch_violations_rig.py -q rig_queries/sast_violations.json
```

## 📁 Repository Structure

### Core Tools
- **`fetch_violations.py`** - Primary tool with type and status filtering
  - **Types**: ALL, SAST, IAC, SCA, LICENSE  
  - **Status**: OPEN (default), DISMISSED, RESOLVED, CLOSED, ALL
- **`fetch_violations_rig.py`** - Secondary tool using RIG report exports
- **`rig_queries/`** - Pre-built query templates for different violation types

### Supporting Files
- **`download-cycode-report/`** - Cycode's example RIG implementation
- **`cycode_policy_sync.py`** - SAST policy management tool
- **`comprehensive_test/`** - Sample output data
- **`sast_policies.yaml`** - SAST policy configurations

## 🔧 Tools Comparison

### Direct GraphQL (`fetch_violations.py`)
**Best for: Real-time security monitoring and detailed analysis**

✅ **Advantages:**
- Rich vulnerability metadata (EPSS scores, CVE advisories)
- Real-time data (38ms response time)
- Exploitability information
- Full dependency paths
- Future-proof (Cycode's preferred approach)

📊 **Data Quality:**
```json
{
  "vulnerability_id": "CVE-2024-12798",
  "package_name": "ch.qos.logback:logback-core",
  "severity": "Medium",
  "epss_info": {"epss": 0.00174},
  "advisory": {
    "summary": "Expression Language Injection vulnerability",
    "description": "Full CVE description..."
  }
}
```

### RIG Reports (`fetch_violations_rig.py`)
**Best for: Bulk exports and compliance reporting**

✅ **Advantages:**
- Large dataset exports (6,563 SAST violations)
- CSV format support
- Historical reporting capabilities
- Simple flat data structure

📋 **Use Cases:**
- Monthly compliance reports
- Historical trend analysis
- Executive dashboards
- Audit documentation

## 🎯 Usage Examples

### Type and Status Filtering (Primary Approach)
```bash
# Get all open violations (default behavior)
python3 fetch_violations.py --type ALL

# Get SAST violations only (open by default)
python3 fetch_violations.py --type SAST --output-dir sast_results

# Get SCA vulnerabilities with rich CVE data
python3 fetch_violations.py --type SCA --max-pages 5

# Get all SAST violations regardless of status
python3 fetch_violations.py --type SAST --status ALL

# Get dismissed violations for analysis
python3 fetch_violations.py --type SAST --status DISMISSED

# Get Infrastructure as Code violations
python3 fetch_violations.py --type IAC

# Get license violations (subset of SCA)
python3 fetch_violations.py --type LICENSE
```

### RIG Reports (Secondary Approach)
```bash
# Export SAST violations to JSON
python3 fetch_violations_rig.py -q rig_queries/sast_violations.json -o sast_report.json

# Export to CSV for spreadsheets
python3 fetch_violations_rig.py -q rig_queries/all_violations.json -o compliance_report.csv -f CSV

# Get secrets detection data
python3 fetch_violations_rig.py -q rig_queries/secrets_violations.json -o secrets_report.json
```

## 📋 Available RIG Query Templates

- **`rig_queries/sast_violations.json`** - SAST (Static Analysis) violations only
- **`rig_queries/secrets_violations.json`** - Secrets detection violations only
- **`rig_queries/all_violations.json`** - All violation types (SAST + SCA + Secrets)

## 🏆 Recommendations

### Primary Approach: Direct GraphQL
Use `fetch_violations.py` for:
- Daily security monitoring
- Detailed vulnerability analysis
- Risk assessment with EPSS scoring
- Real-time security dashboards

### Secondary Approach: RIG Reports
Use `fetch_violations_rig.py` for:
- Compliance reporting
- Historical analysis
- Bulk data exports
- CSV format requirements

## 📊 Sample Results

### Comprehensive Analysis Output
```
🔢 Total Unique Vulnerabilities: 201
🎯 Total Detection Instances: 201

⚠️ By Severity:
   Critical: 19
   High: 101
   Medium: 69
   Low: 12

📦 By Ecosystem:
   Maven: 113
   NPM: 35
   PyPI: 45
   Composer: 8

🎯 Exploitability Analysis:
   High Risk (>0.1 EPSS): 48
   Medium Risk (0.01-0.1): 25
   Low Risk (<0.01): 128
```

## 🔐 Security Notes

- Keep `secret.yaml` secure and never commit to version control
- Credentials are automatically loaded from environment or config file
- All API calls use proper authentication headers

## 🤝 Support

Both approaches are fully functional and complementary. Choose based on your specific use case:
- **Real-time analysis** → Direct GraphQL
- **Bulk reporting** → RIG Reports

---

*This implementation successfully integrates with Cycode's RIG (Risk Information Graph) system using both modern GraphQL endpoints and legacy report-based queries.*