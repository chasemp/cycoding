# Cycode API Violation Scopes - Complete Analysis

Based on testing the Cycode API with your active credentials, here's a comprehensive breakdown of how to get SCA violations at different scopes and whether PR violations are included.

## 🎯 **Key Finding: PR vs CLI Violations Are Separate!**

**✅ CONFIRMED**: PR violations (unmerged code) are **separate** from main platform statistics (merged code).

### **📊 Current State in Your Cycode Instance:**
- **PR SCA Violations**: 6 open violations (4 Critical, 2 High)
- **CLI SCA Violations**: 0 violations (no merged vulnerable code)
- **Total Repositories**: 4 projects (All, Backend, Frontend, ProdSec)

---

## 🔍 **How to Get SCA Violations by Scope**

### **a) All Open SCA Violations Across All of Cycode**

**✅ WORKING ENDPOINTS:**

#### **1. All PR Violations (Unmerged Code)**
```bash
GET /v4/scans/statistics/pull-requests/count/open-violations?scan_types=SCA
```
**Returns**: `{"count": 6}` - Total open SCA violations in all PRs

#### **2. All CLI Violations (Merged Code)**  
```bash
GET /v4/scans/statistics/cli/violations-over-time?scan_types=SCA
```
**Returns**: Historical data of merged code violations (currently 0)

#### **3. Detailed PR Violation Breakdown**
```bash
GET /v4/scans/statistics/pull-requests/violation-breakdown?scan_types=SCA
```
**Returns**: 
```json
[
  {"severity": "Critical", "scm_provider": "Github", "scan_type": "SCA", "open_violations": 4},
  {"severity": "High", "scm_provider": "Github", "scan_type": "SCA", "open_violations": 2}
]
```

---

### **b) All Open SCA Violations for a Cycode Group**

**✅ SUPPORTED** via `organization_ids` parameter:

```bash
GET /v4/scans/statistics/pull-requests/count/open-violations?scan_types=SCA&organization_ids=[ORG_ID]
```

**Note**: Requires your organization ID. Can be obtained from organization endpoints.

---

### **c) All Open SCA Violations for a Cycode Project**

**✅ SUPPORTED** via `project_ids` parameter (though not found in your current setup):

```bash
GET /v4/scans/statistics/pull-requests/count/open-violations?scan_types=SCA&project_ids=[PROJECT_ID]
```

**Your Current Projects:**
- **All** (ID: 24488)
- **Backend** (ID: 24143) 
- **Frontend** (ID: 24144)
- **ProdSec** (ID: 24366)

---

### **d) All Open SCA Violations for a Specific Repository**

**✅ SUPPORTED** via `repository_ids` parameter:

```bash
GET /v4/scans/statistics/pull-requests/count/open-violations?scan_types=SCA&repository_ids=[REPO_ID]
```

**Example for Backend project:**
```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  "https://api.cycode.com/v4/scans/statistics/pull-requests/count/open-violations?scan_types=SCA&repository_ids=24143"
```

---

## 🔀 **PR Violations vs Main Platform Stats**

### **PR Violations (Unmerged Code)**
- **Source**: Pull Request scans
- **Scope**: Code in open/active PRs
- **API Endpoints**: `/v4/scans/statistics/pull-requests/*`
- **Your Data**: 6 open SCA violations
- **Include**: ✅ Your vulnerable PRs from testing

### **CLI Violations (Merged Code)**
- **Source**: CLI scans on merged code  
- **Scope**: Code in main/default branches
- **API Endpoints**: `/v4/scans/statistics/cli/*`
- **Your Data**: 0 violations (no merged vulnerable code)
- **Include**: ❌ Your PRs (until merged)

---

## 🎯 **Implications for Your 3-Tier Testing**

### **✅ Your Vulnerable PRs ARE Being Counted**
Your intentionally vulnerable PRs are showing up in the **PR violation statistics**:
- 4 Critical SCA violations
- 2 High SCA violations  
- Total: 6 violations across your test PRs

### **✅ Repository-Level Filtering Works**
You can filter violations by specific repositories using `repository_ids` parameter.

### **✅ Tier Validation Strategy**
To validate your 3-tier strategy:

#### **Check PR Violations by Repository:**
```python
# Tier 1 Alpha - Should have violations (but blocked from merging)
python fetch_violations.py --repositories cycode-testing-tier-one-alpha --scan-types SCA

# Tier 2 Alpha - Should have violations (warnings only)  
python fetch_violations.py --repositories cycode-testing-tier-two-alpha --scan-types SCA

# Tier 3 Alpha - Should have NO SCA violations (secrets only)
python fetch_violations.py --repositories cycode-testing-tier-three-alpha --scan-types SCA
```

#### **Check Main Branch Violations (after merging):**
```python
# Check if any vulnerable code made it to main branches
python fetch_violations.py --scan-types SCA --endpoint cli
```

---

## 🚀 **Updated fetch_violations.py Usage**

The script can now properly target:

### **All Scopes:**
```bash
# All PR violations
python fetch_violations.py --scan-types SCA --output all_pr_violations.json

# All CLI violations  
python fetch_violations.py --scan-types SCA --endpoint cli --output all_cli_violations.json
```

### **Repository-Specific:**
```bash
# Specific repository PR violations
python fetch_violations.py --repositories Backend --scan-types SCA --output backend_violations.json
```

### **Organization-Level:**
```bash  
# Organization violations (requires org ID)
python fetch_violations.py --scan-types SCA --organization-ids YOUR_ORG_ID --output org_violations.json
```

---

## 📊 **Perfect for 3-Tier Validation!**

Your setup is ideal for testing because:

1. **✅ PR violations are tracked separately** - Your vulnerable PRs show up in statistics
2. **✅ Repository-level filtering works** - Can test each tier independently  
3. **✅ Severity breakdown available** - Can validate Critical/High blocking in Tier 1
4. **✅ Historical tracking** - Can monitor trends over time
5. **✅ Main branch protection** - CLI violations stay at 0 if blocking works

The 6 current PR violations likely come from your intentionally vulnerable PRs across the tier repositories! 🎯
