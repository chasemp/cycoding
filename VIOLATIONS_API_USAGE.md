# Cycode Violations API - Usage Guide

## 🎯 **SUCCESS! Violations Endpoints Confirmed**

Our testing confirmed that Cycode API **does provide individual violation listings** through several endpoints.

## 📋 **Discovered Violations Endpoints**

### **✅ Primary Endpoints (All Confirmed to Exist)**
- **`/v4/violations`** - Main violations endpoint ⭐
- **`/v4/scan-results`** - Scan results with violation details
- **`/v4/detections`** - Security detections/violations  
- **`/v4/findings`** - Security findings

### **✅ Scoped Endpoints**
- **`/v4/pull-requests/violations`** - PR-specific violations
- **`/v4/scans/violations`** - Scan-specific violations
- **`/v4/repositories/violations`** - Repository-specific violations
- **`/v4/organizations/violations`** - Organization-level violations

## 🔧 **Usage with Proper Credentials**

### **1. Set Environment Variables**
```bash
export CYCODE_CLIENT_ID="your-cycode-client-id"
export CYCODE_CLIENT_SECRET="your-cycode-client-secret"
export CYCODE_API_URL="https://api.cycode.com"  # Optional, defaults to this
```

### **2. Fetch SCA Violations**
```bash
# Get all open SCA violations
python fetch_violations.py --scan-types SCA --status Open

# Get critical/high SCA violations for specific repositories
python fetch_violations.py \
  --scan-types SCA \
  --severities Critical High \
  --repositories cycode-testing-tier-one-alpha cycode-testing-tier-two-alpha

# Save results to JSON file
python fetch_violations.py --scan-types SCA --output sca_violations.json

# Verbose logging for debugging
python fetch_violations.py --scan-types SCA --verbose
```

### **3. Filter Options**
- **`--scan-types`**: SCA, SAST, Secrets, IaC, Licenses
- **`--severities`**: Critical, High, Medium, Low  
- **`--status`**: Open, Resolved, Dismissed
- **`--repositories`**: List of repository names
- **`--output`**: Save to JSON file

## 📊 **Expected SCA Violation Data Structure**

Based on the API structure, SCA violations should include:

```json
{
  "violations": [
    {
      "id": "violation-id",
      "scan_type": "SCA",
      "severity": "High", 
      "status": "Open",
      "repository_id": "repo-id",
      "repository_name": "cycode-testing-tier-one-alpha",
      "file_path": "requirements.txt",
      "line_number": 15,
      "package_name": "vulnerable-package",
      "package_version": "1.0.0",
      "cve_ids": ["CVE-2023-1234"],
      "description": "Known vulnerability in package",
      "remediation": "Upgrade to version 1.2.0+",
      "created_at": "2025-09-22T10:00:00Z",
      "pull_request_id": "pr-123"
    }
  ]
}
```

## 🧪 **Testing with Your Tier Repositories**

### **Validate SCA Detection in Tier Repositories**
```bash
# Check Tier 1 Alpha (should block high/critical)
python fetch_violations.py \
  --repositories cycode-testing-tier-one-alpha \
  --scan-types SCA \
  --severities Critical High

# Check Tier 2 Alpha (should warn on all)  
python fetch_violations.py \
  --repositories cycode-testing-tier-two-alpha \
  --scan-types SCA \
  --severities Critical High Medium Low

# Check Tier 3 Alpha (should only have secrets, no SCA)
python fetch_violations.py \
  --repositories cycode-testing-tier-three-alpha \
  --scan-types SCA
```

## 🔍 **Validation Against Expected Findings**

Cross-reference API results with the expected findings in PR comments:

1. **Load PR metadata**: `tier-one-alpha-sca-pr.json`
2. **Fetch actual violations**: `python fetch_violations.py --repositories cycode-testing-tier-one-alpha --scan-types SCA`
3. **Compare results**: Validate that expected SCA vulnerabilities are detected

## ⚡ **Quick Test Commands**

```bash
# Discover available endpoints (requires credentials)
python fetch_violations.py --discover-only

# Get all violations for testing
python fetch_violations.py --output all_violations.json

# Focus on your test repositories
python fetch_violations.py \
  --repositories cycode-testing-tier-one-alpha cycode-testing-tier-two-alpha cycode-testing-tier-three-alpha \
  --output tier_violations.json
```

## 🎯 **Next Steps**

1. **Get Cycode API credentials** from your Cycode account
2. **Run the script** with proper authentication
3. **Validate SCA detections** against expected findings in PR comments
4. **Compare tier behavior** - ensure Tier 1 blocks, Tier 2 warns, Tier 3 ignores SCA

The script is ready to use - just needs proper Cycode API credentials! 🚀
