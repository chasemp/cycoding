#!/usr/bin/env python3
"""
Cycode Violation Fetcher with Type Filtering

This script fetches detailed violation information from Cycode using direct GraphQL queries.
Supports filtering by violation type: ALL, SAST, IAC, SCA, LICENSE

Features:
- Real-time GraphQL queries with rich vulnerability data
- CVE details, EPSS scores, and exploitability information
- Flexible violation type filtering
- Comprehensive analysis and reporting
"""

import sys
import os
import json
import yaml
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add the download-cycode-report directory to the path
sys.path.append('download-cycode-report')

import cycode_lib.cycode_token as tok
import cycode_lib.rig_functions as rig


class CycodeViolationFetcher:
    """Fetcher for Cycode violations with type filtering support"""
    
    def __init__(self, config_file: str = 'secret.yaml'):
        """Initialize the fetcher with credentials from config file"""
        self.config_file = config_file
        self.cycode_api_url = 'https://api.cycode.com'
        self.token = None
        self.load_credentials()
    
    def load_credentials(self):
        """Load Cycode credentials from YAML config file"""
        try:
            with open(self.config_file, 'r') as f:
                secrets = yaml.safe_load(f)
            
            self.client_id = secrets['cycode']['client_id']
            self.client_secret = secrets['cycode']['client_secret']
            
            print(f"✅ Loaded credentials for client: {self.client_id}")
            
        except FileNotFoundError:
            print(f"❌ Config file not found: {self.config_file}")
            sys.exit(1)
        except KeyError as e:
            print(f"❌ Missing credential in config file: {e}")
            sys.exit(1)
    
    def authenticate(self):
        """Authenticate with Cycode API and get JWT token"""
        try:
            self.token = tok.get_cycode_token(
                client_id=self.client_id,
                client_secret=self.client_secret,
                cycode_api_url=self.cycode_api_url
            )
            print("✅ Authentication successful!")
            return True
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False
    
    def get_violation_filters(self, violation_type: str, status: str = 'OPEN') -> List[Dict[str, Any]]:
        """Get GraphQL filters based on violation type and status"""
        violation_type = violation_type.upper()
        status = status.upper()
        
        # Base filters for violation type
        filters = []
        
        # Add category filter
        if violation_type == 'ALL':
            pass  # No category filter - get all violation types
        elif violation_type == 'SAST':
            filters.append({"name": "category", "operator": "Eq", "value": "SAST", "type": "String"})
        elif violation_type == 'IAC':
            filters.append({"name": "category", "operator": "Eq", "value": "IaC", "type": "String"})
        elif violation_type == 'SCA':
            filters.append({"name": "category", "operator": "Eq", "value": "SCA", "type": "String"})
        elif violation_type == 'LICENSE':
            # For license violations, we need to use a different approach
            # since the GraphQL API doesn't support nested filters well
            filters.append({"name": "category", "operator": "Eq", "value": "SCA", "type": "String"})
        else:
            raise ValueError(f"Invalid violation type: {violation_type}. Must be one of: ALL, SAST, IAC, SCA, LICENSE")
        
        # Add status filter (unless requesting ALL statuses)
        if status != 'ALL':
            status_value = self.get_status_value(status)
            filters.append({"name": "status", "operator": "Eq", "value": status_value, "type": "List"})
        
        return filters
    
    def get_status_value(self, status: str) -> str:
        """Convert status argument to API value"""
        status = status.upper()
        status_mapping = {
            'OPEN': 'Open',
            'DISMISSED': 'Dismissed', 
            'RESOLVED': 'Resolved',
            'CLOSED': 'Closed'
        }
        
        if status not in status_mapping:
            raise ValueError(f"Invalid status: {status}. Must be one of: OPEN, DISMISSED, RESOLVED, CLOSED, ALL")
        
        return status_mapping[status]
    
    def classify_repository_tier(self, repo_name: str, tags: list = None, labels: list = None) -> str:
        """Classify repository into tier based on name, tags, and labels"""
        if tags is None:
            tags = []
        if labels is None:
            labels = []
        
        # Check tags and labels for tier information
        all_metadata = [str(item).lower() for item in tags + labels]
        
        for item in all_metadata:
            if any(pattern in item for pattern in ['tier1', 'tier-1', 'tier_1']):
                return 'TIER1'
            elif any(pattern in item for pattern in ['tier2', 'tier-2', 'tier_2']):
                return 'TIER2'
            elif any(pattern in item for pattern in ['tier3', 'tier-3', 'tier_3']):
                return 'TIER3'
        
        # Check repository name for tier information
        repo_lower = repo_name.lower()
        if any(pattern in repo_lower for pattern in ['tier-one', 'tier1', 'tier_one']):
            return 'TIER1'
        elif any(pattern in repo_lower for pattern in ['tier-two', 'tier2', 'tier_two']):
            return 'TIER2'
        elif any(pattern in repo_lower for pattern in ['tier-three', 'tier3', 'tier_three']):
            return 'TIER3'
        
        return 'OTHER'
    
    def fetch_package_vulnerabilities_direct(self, page_size: int = 100, max_pages: int = None) -> List[Dict[str, Any]]:
        """
        Fetch package vulnerabilities using direct GraphQL queries
        This provides the richest vulnerability data with CVE details, advisory info, etc.
        """
        print("🔍 Fetching package vulnerabilities via direct GraphQL...")
        
        query_data = {
            'connections': [{
                'connections': [],
                'exists': True,
                'is_optional': False,
                'resource_type': 'detection',
                'edge_type': 'associated_with',
                'edge_direction': 'outbound',
                'filters': [],
                'variables': [],
                'edge_filters': [],
                'edge_columns': [],
                'parent_resource_type': 'package_vulnerability',
                'edge_opposite_type': 'associated_with',
                'edge_type_id': 'package_vulnerability_associated_with_detection_edge',
                'sort_by': None,
                'sort_order': 'Asc',
                'limit': None
            }],
            'exists': True,
            'is_optional': False,
            'resource_type': 'package_vulnerability',
            'edge_type': '',
            'filters': [],
            'variables': [],
            'edge_filters': [],
            'edge_columns': [],
            'parent_resource_type': '',
            'sort_by': '_key',
            'sort_order': 'Asc',
            'limit': -1,
            'fast_query': True
        }
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        all_results = []
        page_number = 0
        
        while True:
            url = f'{self.cycode_api_url}/graph/api/v1/graph/query?mode=AlertWhen&page_number={page_number}&page_size={page_size}'
            
            print(f"   Fetching page {page_number + 1}...")
            response = requests.post(url, headers=headers, json=query_data)
            
            if not response.ok:
                print(f"❌ Error fetching page {page_number}: {response.status_code} - {response.text}")
                break
            
            result = response.json()
            page_results = result.get('result', [])
            all_results.extend(page_results)
            
            print(f"   ✅ Page {page_number + 1}: {len(page_results)} records")
            
            # Check if we should continue
            total = result.get('total', 0)
            current_count = len(all_results)
            
            if current_count >= total or len(page_results) < page_size:
                break
                
            if max_pages and page_number + 1 >= max_pages:
                print(f"   ⚠️ Reached max pages limit ({max_pages})")
                break
            
            page_number += 1
        
        print(f"✅ Fetched {len(all_results)} package vulnerabilities via direct GraphQL")
        return all_results
    
    def fetch_violations_by_type(self, violation_type: str = 'ALL', status: str = 'OPEN', page_size: int = 100, max_pages: int = None) -> List[Dict[str, Any]]:
        """
        Fetch violations by type using direct GraphQL queries
        violation_type: ALL, SAST, IAC, SCA, LICENSE
        status: OPEN, DISMISSED, RESOLVED, CLOSED, ALL
        """
        status_desc = f" ({status})" if status != 'OPEN' else ""
        print(f"🔍 Fetching {violation_type}{status_desc} violations via direct GraphQL...")
        
        # Get filters for the specified violation type and status
        filters = self.get_violation_filters(violation_type, status)
        
        # For SCA violations, use package vulnerability approach for richer data
        if violation_type.upper() in ['SCA', 'LICENSE']:
            violations = self.fetch_package_vulnerabilities_direct(page_size, max_pages)
            
            # Apply status filtering to SCA/LICENSE violations if needed
            if status.upper() != 'ALL':
                filtered_violations = []
                status_value = self.get_status_value(status)
                for violation in violations:
                    # Check status in the connected detections
                    connections = violation.get('connections', [])
                    for connection in connections:
                        detection = connection.get('resource', {})
                        if detection.get('status') == status_value:
                            filtered_violations.append(violation)
                            break  # Only need one matching detection
                violations = filtered_violations
                print(f"🔍 Filtered to {len(violations)} {status} SCA violations")
            
            # For LICENSE violations, filter to only license-related policies
            if violation_type.upper() == 'LICENSE':
                license_violations = []
                for violation in violations:
                    # Check policy names in connected detections
                    connections = violation.get('connections', [])
                    for connection in connections:
                        detection = connection.get('resource', {})
                        policy_name = detection.get('source_policy_name', '').lower()
                        if 'license' in policy_name or 'non-permissive' in policy_name:
                            license_violations.append(violation)
                            break  # Only need one matching detection
                print(f"🔍 Filtered {len(license_violations)} license violations from {len(violations)} SCA violations")
                return license_violations
            
            return violations
        
        # For other types, use detection-based approach
        return self.fetch_detections_direct(filters=filters, page_size=page_size, max_pages=max_pages)
    
    def fetch_detections_direct(self, filters: List[Dict] = None, page_size: int = 100, max_pages: int = None) -> List[Dict[str, Any]]:
        """
        Fetch detections using direct GraphQL queries
        This can be used for SAST, IAC, Secrets, or other detection types
        """
        violation_types = [f['value'] for f in filters if f.get('name') == 'category'] if filters else ['ALL']
        violation_type_str = ', '.join(violation_types) if violation_types != ['ALL'] else 'ALL'
        print(f"🔍 Fetching {violation_type_str} detections via direct GraphQL...")
        
        if filters is None:
            filters = []
        
        query_data = {
            'connections': [],
            'exists': True,
            'is_optional': False,
            'resource_type': 'detection',
            'edge_type': '',
            'filters': filters,
            'variables': [],
            'edge_filters': [],
            'edge_columns': [],
            'parent_resource_type': '',
            'sort_by': '_key',
            'sort_order': 'Asc',
            'limit': -1,
            'fast_query': True
        }
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        all_results = []
        page_number = 0
        
        while True:
            url = f'{self.cycode_api_url}/graph/api/v1/graph/query?mode=AlertWhen&page_number={page_number}&page_size={page_size}'
            
            print(f"   Fetching page {page_number + 1}...")
            response = requests.post(url, headers=headers, json=query_data)
            
            if not response.ok:
                print(f"❌ Error fetching page {page_number}: {response.status_code} - {response.text}")
                break
            
            result = response.json()
            page_results = result.get('result', [])
            all_results.extend(page_results)
            
            print(f"   ✅ Page {page_number + 1}: {len(page_results)} records")
            
            # Check if we should continue
            total = result.get('total', 0)
            current_count = len(all_results)
            
            if current_count >= total or len(page_results) < page_size:
                break
                
            if max_pages and page_number + 1 >= max_pages:
                print(f"   ⚠️ Reached max pages limit ({max_pages})")
                break
            
            page_number += 1
        
        print(f"✅ Fetched {len(all_results)} detection records via direct GraphQL")
        return all_results
    
    def analyze_package_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze package vulnerabilities and generate comprehensive statistics"""
        if not vulnerabilities:
            return {"total": 0}
        
        analysis = {
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": {},
            "by_ecosystem": {},
            "by_package": {},
            "by_cve": {},
            "by_repository": {},
            "exploitability_stats": {"exploitable": 0, "not_exploitable": 0, "unknown": 0},
            "epss_stats": {"high_epss": 0, "medium_epss": 0, "low_epss": 0},
            "patch_availability": {"patched": 0, "unpatched": 0},
            "detections_count": 0,
            "repo_details": {}  # Detailed per-repository breakdown
        }
        
        for vuln in vulnerabilities:
            resource = vuln.get('resource', {})
            
            # Basic vulnerability info
            severity = resource.get('severity', 'Unknown')
            ecosystem = resource.get('ecosystem', 'Unknown')
            package_name = resource.get('package_name', 'Unknown')
            vuln_id = resource.get('vulnerability_id', 'Unknown')
            
            analysis["by_severity"][severity] = analysis["by_severity"].get(severity, 0) + 1
            analysis["by_ecosystem"][ecosystem] = analysis["by_ecosystem"].get(ecosystem, 0) + 1
            analysis["by_package"][package_name] = analysis["by_package"].get(package_name, 0) + 1
            analysis["by_cve"][vuln_id] = analysis["by_cve"].get(vuln_id, 0) + 1
            
            # Exploitability analysis
            exploitability = resource.get('exploitability')
            if exploitability:
                analysis["exploitability_stats"]["exploitable"] += 1
            elif exploitability is False:
                analysis["exploitability_stats"]["not_exploitable"] += 1
            else:
                analysis["exploitability_stats"]["unknown"] += 1
            
            # EPSS analysis
            epss_info = resource.get('epss_info', {})
            epss_score = epss_info.get('epss', 0)
            epss_risk = "High" if epss_score > 0.1 else "Medium" if epss_score > 0.01 else "Low"
            
            if epss_score > 0.1:
                analysis["epss_stats"]["high_epss"] += 1
            elif epss_score > 0.01:
                analysis["epss_stats"]["medium_epss"] += 1
            else:
                analysis["epss_stats"]["low_epss"] += 1
            
            # Patch availability
            version_ranges = resource.get('vulnerable_version_ranges', [])
            has_patch = any(vr.get('first_patched_version') for vr in version_ranges)
            if has_patch:
                analysis["patch_availability"]["patched"] += 1
            else:
                analysis["patch_availability"]["unpatched"] += 1
            
            # Count detections (actual instances in repositories)
            connections = vuln.get('connections', [])
            analysis["detections_count"] += len(connections)
            
            # Repository analysis from detections with detailed breakdown
            for connection in connections:
                detection = connection.get('resource', {})
                source_entity = detection.get('source_entity_name', 'Unknown')
                analysis["by_repository"][source_entity] = analysis["by_repository"].get(source_entity, 0) + 1
                
                # Classify repository tier
                tags = detection.get('tags', [])
                labels = detection.get('labels', [])
                tier = self.classify_repository_tier(source_entity, tags, labels)
                
                # Detailed per-repository analysis
                if source_entity not in analysis["repo_details"]:
                    analysis["repo_details"][source_entity] = {
                        'total': 0,
                        'severities': {},
                        'ecosystems': {},
                        'packages': {},
                        'epss_risk': {'High': 0, 'Medium': 0, 'Low': 0},
                        'tier': tier,
                        'tags': tags,
                        'labels': labels
                    }
                
                repo_detail = analysis["repo_details"][source_entity]
                repo_detail['total'] += 1
                repo_detail['severities'][severity] = repo_detail['severities'].get(severity, 0) + 1
                repo_detail['ecosystems'][ecosystem] = repo_detail['ecosystems'].get(ecosystem, 0) + 1
                repo_detail['packages'][package_name] = repo_detail['packages'].get(package_name, 0) + 1
                repo_detail['epss_risk'][epss_risk] += 1
        
        return analysis
    
    def print_comprehensive_summary(self, analysis: Dict[str, Any], show_per_repo: bool = False, show_per_tier: bool = False):
        """Print comprehensive analysis summary"""
        print("\n" + "="*100)
        print("📊 COMPREHENSIVE CYCODE VULNERABILITY ANALYSIS")
        print("="*100)
        
        print(f"🔢 Total Unique Vulnerabilities: {analysis.get('total_vulnerabilities', 0)}")
        print(f"🎯 Total Detection Instances: {analysis.get('detections_count', 0)}")
        
        if analysis.get('by_severity'):
            print(f"\n⚠️ By Severity:")
            for severity, count in sorted(analysis['by_severity'].items()):
                print(f"   {severity}: {count}")
        
        if analysis.get('by_ecosystem'):
            print(f"\n📦 By Ecosystem:")
            for ecosystem, count in sorted(analysis['by_ecosystem'].items()):
                print(f"   {ecosystem}: {count}")
        
        if analysis.get('by_repository'):
            print(f"\n🏗️ By Repository (Detection Instances):")
            for repo, count in sorted(analysis['by_repository'].items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"   {repo}: {count}")
        
        print(f"\n🎯 Exploitability Analysis:")
        exp_stats = analysis.get('exploitability_stats', {})
        print(f"   Exploitable: {exp_stats.get('exploitable', 0)}")
        print(f"   Not Exploitable: {exp_stats.get('not_exploitable', 0)}")
        print(f"   Unknown: {exp_stats.get('unknown', 0)}")
        
        print(f"\n📈 EPSS Score Distribution:")
        epss_stats = analysis.get('epss_stats', {})
        print(f"   High Risk (>0.1): {epss_stats.get('high_epss', 0)}")
        print(f"   Medium Risk (0.01-0.1): {epss_stats.get('medium_epss', 0)}")
        print(f"   Low Risk (<0.01): {epss_stats.get('low_epss', 0)}")
        
        print(f"\n🔧 Patch Availability:")
        patch_stats = analysis.get('patch_availability', {})
        print(f"   Patched: {patch_stats.get('patched', 0)}")
        print(f"   Unpatched: {patch_stats.get('unpatched', 0)}")
        
        # Add tier analysis for SCA
        if analysis.get('repo_details'):
            tier_summary = {}
            for repo_name, details in analysis['repo_details'].items():
                tier = details.get('tier', 'OTHER')
                tier_summary[tier] = tier_summary.get(tier, 0) + details['total']
            
            if tier_summary:
                print(f"\n🏷️ By Tier (Detection Instances):")
                for tier, count in sorted(tier_summary.items()):
                    print(f"   {tier}: {count}")
        
        # Add detailed per-repository breakdown for SCA (optional)
        if show_per_repo and analysis.get('repo_details'):
            self.print_sca_repository_breakdown(analysis['repo_details'])
        
        # Add detailed per-tier breakdown for SCA (optional)
        if show_per_tier and analysis.get('repo_details'):
            self.print_sca_tier_breakdown(analysis['repo_details'])
        
        print("="*100)
    
    def print_sca_repository_breakdown(self, repo_details: Dict[str, Dict]):
        """Print detailed per-repository breakdown for SCA violations"""
        if not repo_details:
            return
        
        print(f"\n" + "="*100)
        print(f"📈 DETAILED REPOSITORY BREAKDOWN - SCA VULNERABILITIES")
        print("="*100)
        
        # Sort repositories by total violations (descending)
        sorted_repos = sorted(repo_details.items(), key=lambda x: x[1]['total'], reverse=True)
        
        for repo_name, details in sorted_repos:
            print(f"\n🏗️ {repo_name}")
            print(f"   Total Vulnerabilities: {details['total']}")
            
            # Severity breakdown for this repo
            if details['severities']:
                severity_items = sorted(details['severities'].items(), key=lambda x: x[1], reverse=True)
                severity_str = ", ".join([f"{sev}: {count}" for sev, count in severity_items])
                print(f"   Severities: {severity_str}")
            
            # Ecosystem breakdown for this repo
            if details['ecosystems']:
                eco_items = sorted(details['ecosystems'].items(), key=lambda x: x[1], reverse=True)
                eco_str = ", ".join([f"{eco}: {count}" for eco, count in eco_items])
                print(f"   Ecosystems: {eco_str}")
            
            # EPSS risk breakdown for this repo
            if details['epss_risk']:
                epss_items = sorted(details['epss_risk'].items(), key=lambda x: x[1], reverse=True)
                epss_str = ", ".join([f"{risk}: {count}" for risk, count in epss_items if count > 0])
                if epss_str:
                    print(f"   EPSS Risk: {epss_str}")
            
            # Top packages for this repo
            if details['packages']:
                top_packages = sorted(details['packages'].items(), key=lambda x: x[1], reverse=True)[:5]
                print(f"   Top Vulnerable Packages:")
                for package, count in top_packages:
                    package_short = package[:45] + "..." if len(package) > 45 else package
                    print(f"     • {package_short}: {count}")
        
        print("="*100)
    
    def print_sca_tier_breakdown(self, repo_details: Dict[str, Dict]):
        """Print detailed per-tier breakdown for SCA violations"""
        if not repo_details:
            return
        
        print(f"\n" + "="*100)
        print("🏷️ DETAILED TIER BREAKDOWN - SCA")
        print("="*100)
        
        # Group repositories by tier
        tier_groups = {}
        for repo_name, details in repo_details.items():
            tier = details.get('tier', 'OTHER')
            if tier not in tier_groups:
                tier_groups[tier] = {}
            tier_groups[tier][repo_name] = details
        
        # Sort tiers for consistent display
        tier_order = ['TIER1', 'TIER2', 'TIER3', 'OTHER']
        
        for tier in tier_order:
            if tier not in tier_groups:
                continue
                
            tier_repos = tier_groups[tier]
            total_detections = sum(details['total'] for details in tier_repos.values())
            
            print(f"\n🎯 {tier}")
            print(f"   Total Detection Instances: {total_detections}")
            print(f"   Repositories: {len(tier_repos)}")
            
            # Aggregate tier statistics
            tier_severities = {}
            tier_ecosystems = {}
            tier_packages = {}
            tier_epss = {'High': 0, 'Medium': 0, 'Low': 0}
            
            for repo_name, details in tier_repos.items():
                for severity, count in details['severities'].items():
                    tier_severities[severity] = tier_severities.get(severity, 0) + count
                for ecosystem, count in details['ecosystems'].items():
                    tier_ecosystems[ecosystem] = tier_ecosystems.get(ecosystem, 0) + count
                for package, count in details['packages'].items():
                    tier_packages[package] = tier_packages.get(package, 0) + count
                for risk_level, count in details['epss_risk'].items():
                    tier_epss[risk_level] += count
            
            # Show tier-level statistics
            if tier_severities:
                severity_items = sorted(tier_severities.items(), key=lambda x: x[1], reverse=True)
                severity_str = ", ".join([f"{sev}: {count}" for sev, count in severity_items])
                print(f"   Severities: {severity_str}")
            
            if tier_ecosystems:
                eco_items = sorted(tier_ecosystems.items(), key=lambda x: x[1], reverse=True)
                eco_str = ", ".join([f"{eco}: {count}" for eco, count in eco_items])
                print(f"   Ecosystems: {eco_str}")
            
            if tier_epss:
                epss_str = ", ".join([f"{risk}: {count}" for risk, count in tier_epss.items() if count > 0])
                print(f"   EPSS Risk: {epss_str}")
            
            # Show top packages for this tier
            if tier_packages:
                top_packages = sorted(tier_packages.items(), key=lambda x: x[1], reverse=True)[:5]
                print(f"   Top Packages:")
                for package, count in top_packages:
                    print(f"     • {package}: {count}")
            
            # Show repositories in this tier
            sorted_repos = sorted(tier_repos.items(), key=lambda x: x[1]['total'], reverse=True)
            print(f"   Repositories:")
            for repo_name, details in sorted_repos:
                print(f"     • {repo_name}: {details['total']} detections")
        
        print("="*100)
    
    def save_results(self, data: Any, output_file: str):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✅ Results saved to: {output_file}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")
    
    def run_violation_fetch(self, violation_type: str = 'ALL', status: str = 'OPEN', output_dir: str = "violation_results", page_size: int = 100, max_pages: int = None, per_repo: bool = False, per_tier: bool = False):
        """Run violation fetch for specified type and status"""
        status_desc = f" ({status})" if status != 'OPEN' else ""
        print(f"🚀 Starting {violation_type}{status_desc} violation fetch...")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Authenticate
        if not self.authenticate():
            return False
        
        try:
            print("\n" + "="*80)
            print(f"📊 FETCHING {violation_type.upper()}{status_desc.upper()} VIOLATIONS")
            print("="*80)
            
            # Fetch violations by type and status
            violations = self.fetch_violations_by_type(
                violation_type=violation_type,
                status=status,
                page_size=page_size,
                max_pages=max_pages
            )
            
            if violations:
                # Generate output filename
                output_file = os.path.join(output_dir, f"{violation_type.lower()}_violations_{timestamp}.json")
                self.save_results(violations, output_file)
                
                # Analyze results based on violation type
                if violation_type.upper() in ['SCA', 'LICENSE']:
                    analysis = self.analyze_package_vulnerabilities(violations)
                    self.print_comprehensive_summary(analysis, show_per_repo=per_repo, show_per_tier=per_tier)
                    
                    # Save analysis
                    analysis_file = os.path.join(output_dir, f"{violation_type.lower()}_analysis_{timestamp}.json")
                    self.save_results(analysis, analysis_file)
                else:
                    # For non-SCA violations, provide basic analysis
                    self.print_basic_violation_summary(violations, violation_type, show_per_repo=per_repo, show_per_tier=per_tier)
            else:
                print(f"⚠️ No {violation_type} violations found")
            
            print(f"\n✅ {violation_type} violation fetch completed!")
            print(f"📁 Results saved to: {output_dir}/")
            
            return True
                
        except Exception as e:
            print(f"❌ Error during {violation_type} violation fetch: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def print_basic_violation_summary(self, violations: List[Dict[str, Any]], violation_type: str, show_per_repo: bool = False, show_per_tier: bool = False):
        """Print basic summary for non-SCA violations"""
        if not violations:
            return
        
        print("\n" + "="*80)
        print(f"📊 {violation_type.upper()} VIOLATIONS SUMMARY")
        print("="*80)
        
        print(f"🔢 Total Violations: {len(violations)}")
        
        # Analyze by severity
        severity_count = {}
        repo_count = {}
        policy_count = {}
        repo_details = {}  # For detailed per-repo breakdown
        tier_count = {}  # For tier analysis
        
        for violation in violations:
            resource = violation.get('resource', {})
            
            severity = resource.get('severity', 'Unknown')
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            repo = resource.get('source_entity_name', 'Unknown')
            repo_count[repo] = repo_count.get(repo, 0) + 1
            
            policy = resource.get('source_policy_name', 'Unknown')
            policy_count[policy] = policy_count.get(policy, 0) + 1
            
            # Classify repository tier
            tags = resource.get('tags', [])
            labels = resource.get('labels', [])
            tier = self.classify_repository_tier(repo, tags, labels)
            tier_count[tier] = tier_count.get(tier, 0) + 1
            
            # Detailed per-repo analysis
            if repo not in repo_details:
                repo_details[repo] = {'total': 0, 'severities': {}, 'policies': {}, 'tier': tier, 'tags': tags, 'labels': labels}
            
            repo_details[repo]['total'] += 1
            repo_details[repo]['severities'][severity] = repo_details[repo]['severities'].get(severity, 0) + 1
            repo_details[repo]['policies'][policy] = repo_details[repo]['policies'].get(policy, 0) + 1
        
        if severity_count:
            print(f"\n⚠️ By Severity:")
            for severity, count in sorted(severity_count.items()):
                print(f"   {severity}: {count}")
        
        if repo_count:
            print(f"\n🏗️ By Repository:")
            for repo, count in sorted(repo_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"   {repo}: {count}")
        
        if policy_count:
            print(f"\n📋 Top Policies:")
            for policy, count in sorted(policy_count.items(), key=lambda x: x[1], reverse=True)[:5]:
                policy_short = policy[:60] + "..." if len(policy) > 60 else policy
                print(f"   {policy_short}: {count}")
        
        if tier_count:
            print(f"\n🏷️ By Tier:")
            for tier, count in sorted(tier_count.items()):
                print(f"   {tier}: {count}")
        
        # Detailed per-repository breakdown (optional)
        if show_per_repo:
            self.print_repository_breakdown(repo_details, violation_type)
        
        # Detailed per-tier breakdown (optional)
        if show_per_tier:
            self.print_tier_breakdown(repo_details, violation_type)
        
        print("="*80)
    
    def print_tier_breakdown(self, repo_details: Dict[str, Dict], violation_type: str):
        """Print detailed per-tier breakdown"""
        if not repo_details:
            return
        
        print(f"\n" + "="*80)
        print(f"🏷️ DETAILED TIER BREAKDOWN - {violation_type.upper()}")
        print("="*80)
        
        # Group repositories by tier
        tier_groups = {}
        for repo_name, details in repo_details.items():
            tier = details.get('tier', 'OTHER')
            if tier not in tier_groups:
                tier_groups[tier] = {}
            tier_groups[tier][repo_name] = details
        
        # Sort tiers for consistent display
        tier_order = ['TIER1', 'TIER2', 'TIER3', 'OTHER']
        
        for tier in tier_order:
            if tier not in tier_groups:
                continue
                
            tier_repos = tier_groups[tier]
            total_violations = sum(details['total'] for details in tier_repos.values())
            
            print(f"\n🎯 {tier}")
            print(f"   Total Violations: {total_violations}")
            print(f"   Repositories: {len(tier_repos)}")
            
            # Aggregate tier statistics
            tier_severities = {}
            tier_policies = {}
            
            for repo_name, details in tier_repos.items():
                for severity, count in details['severities'].items():
                    tier_severities[severity] = tier_severities.get(severity, 0) + count
                for policy, count in details['policies'].items():
                    tier_policies[policy] = tier_policies.get(policy, 0) + count
            
            # Show tier-level severity breakdown
            if tier_severities:
                severity_items = sorted(tier_severities.items(), key=lambda x: x[1], reverse=True)
                severity_str = ", ".join([f"{sev}: {count}" for sev, count in severity_items])
                print(f"   Severities: {severity_str}")
            
            # Show top policies for this tier
            if tier_policies:
                top_policies = sorted(tier_policies.items(), key=lambda x: x[1], reverse=True)[:3]
                print(f"   Top Policies:")
                for policy, count in top_policies:
                    policy_short = policy[:50] + "..." if len(policy) > 50 else policy
                    print(f"     • {policy_short}: {count}")
            
            # Show repositories in this tier
            sorted_repos = sorted(tier_repos.items(), key=lambda x: x[1]['total'], reverse=True)
            print(f"   Repositories:")
            for repo_name, details in sorted_repos:
                print(f"     • {repo_name}: {details['total']} violations")
        
        print("="*80)
        
    def print_repository_breakdown(self, repo_details: Dict[str, Dict], violation_type: str):
        """Print detailed per-repository breakdown"""
        if not repo_details:
            return
        
        print(f"\n" + "="*80)
        print(f"📈 DETAILED REPOSITORY BREAKDOWN - {violation_type.upper()}")
        print("="*80)
        
        # Sort repositories by total violations (descending)
        sorted_repos = sorted(repo_details.items(), key=lambda x: x[1]['total'], reverse=True)
        
        for repo_name, details in sorted_repos:
            print(f"\n🏗️ {repo_name}")
            print(f"   Total Violations: {details['total']}")
            
            # Severity breakdown for this repo
            if details['severities']:
                severity_items = sorted(details['severities'].items(), key=lambda x: x[1], reverse=True)
                severity_str = ", ".join([f"{sev}: {count}" for sev, count in severity_items])
                print(f"   Severities: {severity_str}")
            
            # Top policies for this repo
            if details['policies']:
                top_policies = sorted(details['policies'].items(), key=lambda x: x[1], reverse=True)[:3]
                print(f"   Top Policies:")
                for policy, count in top_policies:
                    policy_short = policy[:50] + "..." if len(policy) > 50 else policy
                    print(f"     • {policy_short}: {count}")
        
        print("="*80)
        

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Cycode Violation Fetcher with Type and Status Filtering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Violation Types:
  ALL      - All violation types (default)
  SAST     - Static Application Security Testing violations
  IAC      - Infrastructure as Code violations
  SCA      - Software Composition Analysis (dependency) violations
  LICENSE  - License violations (subset of SCA)

Violation Status:
  OPEN     - Open violations only (default)
  DISMISSED - Dismissed violations only
  RESOLVED - Resolved violations only  
  CLOSED   - Closed violations only
  ALL      - All violation statuses

Examples:
  python3 fetch_violations.py --type SAST
  python3 fetch_violations.py --type SCA --status OPEN
  python3 fetch_violations.py --type SAST --status ALL --output-dir all_sast
  python3 fetch_violations.py --type SAST --per-repo
  python3 fetch_violations.py --type SCA --per-tier
  python3 fetch_violations.py --type LICENSE --status DISMISSED --per-repo --per-tier
        """
    )
    
    parser.add_argument('-t', '--type', default='ALL', 
                       choices=['ALL', 'SAST', 'IAC', 'SCA', 'LICENSE'],
                       help='Type of violations to fetch (default: ALL)')
    parser.add_argument('-s', '--status', default='OPEN',
                       choices=['OPEN', 'DISMISSED', 'RESOLVED', 'CLOSED', 'ALL'],
                       help='Status of violations to fetch (default: OPEN)')
    parser.add_argument('-o', '--output-dir', default='violation_results', 
                       help='Output directory (default: violation_results)')
    parser.add_argument('-c', '--config', default='secret.yaml', 
                       help='Config file with credentials (default: secret.yaml)')
    parser.add_argument('--page-size', type=int, default=100,
                       help='Number of records per page (default: 100)')
    parser.add_argument('--max-pages', type=int, default=None,
                       help='Maximum number of pages to fetch (default: unlimited)')
    parser.add_argument('--per-repo', action='store_true',
                       help='Show detailed per-repository breakdown')
    parser.add_argument('--per-tier', action='store_true',
                       help='Show detailed per-tier breakdown (TIER1, TIER2, TIER3, OTHER)')
    
    args = parser.parse_args()
    
    # Create fetcher and run
    fetcher = CycodeViolationFetcher(config_file=args.config)
    success = fetcher.run_violation_fetch(
        violation_type=args.type,
        status=args.status,
        output_dir=args.output_dir,
        page_size=args.page_size,
        max_pages=args.max_pages,
        per_repo=args.per_repo,
        per_tier=args.per_tier
    )
    
    if success:
        print(f"\n✅ {args.type} violation fetch completed successfully!")
    else:
        print(f"\n❌ {args.type} violation fetch failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
