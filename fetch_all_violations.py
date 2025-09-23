#!/usr/bin/env python3
"""
Cycode All Violations Fetcher

Comprehensive script to fetch SCA violations from ALL scopes:
- PR violations (unmerged code)  
- CLI violations (merged code)
- Organization, Project, and Repository level filtering
"""

import requests
import json
import os
import logging
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CycodeAllViolationsFetcher:
    """Fetches violations from ALL Cycode scopes and sources"""
    
    def __init__(self, config_file: str = None):
        # Load configuration
        config = self._load_config(config_file)
        
        self.api_url = config.get("api_url") or os.getenv("CYCODE_API_URL", "https://api.cycode.com")
        self.client_id = config.get("client_id") or os.getenv("CYCODE_CLIENT_ID")
        self.client_secret = config.get("client_secret") or os.getenv("CYCODE_CLIENT_SECRET")
        self.access_token = None
        self.session = requests.Session()
        
        if not self.client_id or not self.client_secret:
            logger.error("Cycode API credentials must be provided via config file or environment variables")
            raise ValueError("Missing Cycode API credentials")
    
    def _load_config(self, config_file: str = None) -> Dict[str, str]:
        """Load configuration from YAML file"""
        if not config_file:
            possible_files = ["secret.yaml", "secrets.yaml", "config.yaml", "cycode.yaml"]
            for file_path in possible_files:
                if Path(file_path).exists():
                    config_file = file_path
                    break
        
        if not config_file or not Path(config_file).exists():
            logger.debug("No config file found, using environment variables")
            return {}
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            cycode_config = config.get('cycode', {})
            logger.info(f"Loaded configuration from {config_file}")
            return cycode_config
        except Exception as e:
            logger.warning(f"Failed to load config from {config_file}: {e}")
            return {}
    
    def get_jwt_token(self) -> str:
        """Get JWT access token from Cycode API"""
        logger.info("Getting JWT token...")
        
        token_url = f"{self.api_url}/api/v1/auth/api-token"
        auth_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        payload = {"clientId": self.client_id, "secret": self.client_secret}
        
        try:
            response = requests.post(token_url, json=payload, headers=auth_headers, timeout=180)
            
            if response.status_code == 200:
                token_data = response.json()
                jwt_token = token_data.get('token')
                
                if jwt_token:
                    logger.info("Successfully obtained JWT token")
                    self.access_token = f"Bearer {jwt_token}"
                    return self.access_token
                else:
                    logger.error("JWT token not found in response")
            else:
                logger.error(f"Failed to get JWT token: {response.status_code}")
                logger.debug(f"Response: {response.text}")
                
        except Exception as e:
            logger.error(f"Exception during JWT token request: {e}")
        
        raise ValueError("Failed to obtain JWT token")
    
    def setup_session(self):
        """Setup session with authentication headers"""
        if not self.access_token:
            self.access_token = self.get_jwt_token()
        
        self.session.headers.update({
            "Authorization": self.access_token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
    
    def get_organizations(self) -> List[Dict]:
        """Get list of organizations"""
        # This endpoint might not exist, but we'll try common patterns
        potential_endpoints = [
            "/v4/organizations",
            "/v4/groups", 
            "/v4/hierarchy"
        ]
        
        for endpoint in potential_endpoints:
            try:
                url = f"{self.api_url}{endpoint}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Found organizations endpoint: {endpoint}")
                    return data.get('items', data) if isinstance(data, dict) else data
            except Exception as e:
                logger.debug(f"Organization endpoint {endpoint} failed: {e}")
        
        logger.warning("No organization endpoints found")
        return []
    
    def get_projects(self) -> List[Dict]:
        """Get list of projects/repositories"""
        url = f"{self.api_url}/v4/projects"
        response = self.session.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            projects = data.get('items', [])
            logger.info(f"Found {len(projects)} projects")
            return projects
        else:
            logger.error(f"Failed to get projects: {response.status_code}")
            return []
    
    def fetch_all_violations(self, 
                            scan_types: List[str] = None,
                            severities: List[str] = None,
                            organization_ids: List[str] = None,
                            project_ids: List[str] = None,
                            repository_ids: List[str] = None) -> Dict[str, Any]:
        """
        Fetch violations from ALL sources and scopes
        
        Returns comprehensive violation data including:
        - PR violations (unmerged code)
        - CLI violations (merged code) 
        - Breakdowns by severity, repository, etc.
        """
        
        self.setup_session()
        
        if not scan_types:
            scan_types = ['SCA']
        
        results = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'scan_types': scan_types,
                'severities': severities,
                'filters': {
                    'organization_ids': organization_ids,
                    'project_ids': project_ids,
                    'repository_ids': repository_ids
                }
            },
            'pr_violations': {},
            'cli_violations': {},
            'summary': {}
        }
        
        # Build common parameters
        base_params = {'scan_types': scan_types}
        if severities:
            base_params['severities'] = severities
        if organization_ids:
            base_params['organization_ids'] = organization_ids
        if project_ids:
            base_params['project_ids'] = project_ids  
        if repository_ids:
            base_params['repository_ids'] = repository_ids
        
        logger.info("Fetching PR violations (unmerged code)...")
        results['pr_violations'] = self._fetch_pr_violations(base_params)
        
        logger.info("Fetching CLI violations (merged code)...")
        results['cli_violations'] = self._fetch_cli_violations(base_params)
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _fetch_pr_violations(self, params: Dict) -> Dict[str, Any]:
        """Fetch all PR violation data"""
        pr_data = {}
        
        # 1. Open violations count
        try:
            url = f"{self.api_url}/v4/scans/statistics/pull-requests/count/open-violations"
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                pr_data['open_count'] = response.json()
                logger.info(f"PR open violations: {pr_data['open_count'].get('count', 0)}")
            else:
                logger.warning(f"Failed to get PR open count: {response.status_code}")
                pr_data['open_count'] = {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Error fetching PR open count: {e}")
            pr_data['open_count'] = {'error': str(e)}
        
        # 2. Historical violations
        try:
            url = f"{self.api_url}/v4/scans/statistics/pull-requests/historical-violations"
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                pr_data['historical'] = response.json()
                logger.info(f"PR historical data: {len(pr_data['historical'])} data points")
            else:
                logger.warning(f"Failed to get PR historical: {response.status_code}")
                pr_data['historical'] = {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Error fetching PR historical: {e}")
            pr_data['historical'] = {'error': str(e)}
        
        # 3. Violation breakdown
        try:
            url = f"{self.api_url}/v4/scans/statistics/pull-requests/violation-breakdown"
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                pr_data['breakdown'] = response.json()
                logger.info(f"PR breakdown: {len(pr_data['breakdown'])} categories")
            else:
                logger.warning(f"Failed to get PR breakdown: {response.status_code}")
                pr_data['breakdown'] = {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Error fetching PR breakdown: {e}")
            pr_data['breakdown'] = {'error': str(e)}
        
        # 4. Resolved violations count
        try:
            url = f"{self.api_url}/v4/scans/statistics/pull-requests/count/resolved-violations"
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                pr_data['resolved_count'] = response.json()
                logger.info(f"PR resolved violations: {pr_data['resolved_count'].get('count', 0)}")
            else:
                logger.debug(f"PR resolved count not available: {response.status_code}")
                pr_data['resolved_count'] = {'count': 0, 'note': 'endpoint_unavailable'}
        except Exception as e:
            logger.debug(f"PR resolved count error: {e}")
            pr_data['resolved_count'] = {'count': 0, 'error': str(e)}
        
        # 5. Dismissed violations count  
        try:
            url = f"{self.api_url}/v4/scans/statistics/pull-requests/count/dismissed-violations"
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                pr_data['dismissed_count'] = response.json()
                logger.info(f"PR dismissed violations: {pr_data['dismissed_count'].get('count', 0)}")
            else:
                logger.debug(f"PR dismissed count not available: {response.status_code}")
                pr_data['dismissed_count'] = {'count': 0, 'note': 'endpoint_unavailable'}
        except Exception as e:
            logger.debug(f"PR dismissed count error: {e}")
            pr_data['dismissed_count'] = {'count': 0, 'error': str(e)}
        
        return pr_data
    
    def _fetch_cli_violations(self, params: Dict) -> Dict[str, Any]:
        """Fetch all CLI violation data (merged code)"""
        cli_data = {}
        
        # 1. Violations over time - try both filtered and unfiltered
        try:
            url = f"{self.api_url}/v4/scans/statistics/cli/violations-over-time"
            
            # First try with the provided filters
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                cli_data['over_time'] = response.json()
                total_violations = sum(item.get('violations_count', 0) for item in cli_data['over_time'])
                logger.info(f"CLI violations over time (filtered): {len(cli_data['over_time'])} data points, {total_violations} total violations")
                
                # If no data with filters and we're filtering by scan_types, also get unfiltered data for comparison
                if len(cli_data['over_time']) == 0 and 'scan_types' in params:
                    logger.info("No filtered CLI data found, fetching all CLI violations for comparison...")
                    params_unfiltered = {k: v for k, v in params.items() if k != 'scan_types'}
                    response_all = self.session.get(url, params=params_unfiltered, timeout=15)
                    if response_all.status_code == 200:
                        all_cli_data = response_all.json()
                        total_all_violations = sum(item.get('violations_count', 0) for item in all_cli_data)
                        cli_data['over_time_all_scantypes'] = all_cli_data
                        logger.info(f"CLI violations over time (all scan types): {len(all_cli_data)} data points, {total_all_violations} total violations")
                        
                        # Show breakdown by scan type
                        scan_type_breakdown = {}
                        for item in all_cli_data:
                            scan_type = item.get('scan_type', 'Unknown')
                            violations = item.get('violations_count', 0)
                            scan_type_breakdown[scan_type] = scan_type_breakdown.get(scan_type, 0) + violations
                        logger.info(f"CLI violations by scan type: {scan_type_breakdown}")
            else:
                logger.warning(f"Failed to get CLI over time: {response.status_code}")
                cli_data['over_time'] = {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Error fetching CLI over time: {e}")
            cli_data['over_time'] = {'error': str(e)}
        
        # 2. Scan count
        try:
            url = f"{self.api_url}/v4/scans/statistics/cli/scan-count"
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                cli_data['scan_count'] = response.json()
                logger.info(f"CLI scan count: {cli_data['scan_count']}")
            else:
                logger.debug(f"CLI scan count not available: {response.status_code}")
                cli_data['scan_count'] = {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            logger.debug(f"CLI scan count error: {e}")
            cli_data['scan_count'] = {'error': str(e)}
        
        return cli_data
    
    def _generate_summary(self, results: Dict) -> Dict[str, Any]:
        """Generate summary of all violation data"""
        summary = {
            'total_violations': {
                'pr_open': 0,
                'pr_resolved': 0,
                'pr_dismissed': 0,
                'cli_latest': 0
            },
            'by_severity': {},
            'by_source': {
                'pull_requests': 0,
                'merged_code': 0
            }
        }
        
        # Extract PR counts
        pr_violations = results.get('pr_violations', {})
        
        if 'open_count' in pr_violations and isinstance(pr_violations['open_count'], dict):
            summary['total_violations']['pr_open'] = pr_violations['open_count'].get('count', 0)
        
        if 'resolved_count' in pr_violations and isinstance(pr_violations['resolved_count'], dict):
            summary['total_violations']['pr_resolved'] = pr_violations['resolved_count'].get('count', 0)
        
        if 'dismissed_count' in pr_violations and isinstance(pr_violations['dismissed_count'], dict):
            summary['total_violations']['pr_dismissed'] = pr_violations['dismissed_count'].get('count', 0)
        
        # Extract CLI counts - sum all violations across all scan types and time periods
        cli_violations = results.get('cli_violations', {})
        if 'over_time' in cli_violations and isinstance(cli_violations['over_time'], list):
            total_cli_violations = sum(item.get('violations_count', 0) for item in cli_violations['over_time'])
            summary['total_violations']['cli_latest'] = total_cli_violations
        
        # Also include unfiltered CLI data if available
        if 'over_time_all_scantypes' in cli_violations and isinstance(cli_violations['over_time_all_scantypes'], list):
            total_all_cli_violations = sum(item.get('violations_count', 0) for item in cli_violations['over_time_all_scantypes'])
            summary['total_violations']['cli_all_scantypes'] = total_all_cli_violations
            
            # Add CLI breakdown by scan type
            summary['cli_by_scan_type'] = {}
            for item in cli_violations['over_time_all_scantypes']:
                scan_type = item.get('scan_type', 'Unknown')
                violations = item.get('violations_count', 0)
                summary['cli_by_scan_type'][scan_type] = summary['cli_by_scan_type'].get(scan_type, 0) + violations
        
        # Extract severity breakdown from PR data
        if 'breakdown' in pr_violations and isinstance(pr_violations['breakdown'], list):
            for item in pr_violations['breakdown']:
                severity = item.get('severity', 'Unknown')
                violations = item.get('open_violations', 0)
                if severity in summary['by_severity']:
                    summary['by_severity'][severity] += violations
                else:
                    summary['by_severity'][severity] = violations
        
        # Calculate source totals
        summary['by_source']['pull_requests'] = summary['total_violations']['pr_open']
        summary['by_source']['merged_code'] = summary['total_violations']['cli_latest']
        
        return summary

def main():
    """CLI interface for comprehensive violations fetcher"""
    parser = argparse.ArgumentParser(description='Fetch ALL Cycode SCA violations from all scopes')
    
    # Scope arguments
    parser.add_argument('--scan-types', nargs='+', default=['SCA'], 
                       help='Scan types to filter (default: SCA)')
    parser.add_argument('--severities', nargs='+',
                       help='Severities to filter (Critical, High, Medium, Low)')
    
    # Filtering arguments  
    parser.add_argument('--organization-ids', nargs='+', metavar='ORG_ID',
                       help='Organization IDs to filter by')
    parser.add_argument('--project-ids', nargs='+', metavar='PROJECT_ID', 
                       help='Project IDs to filter by')
    parser.add_argument('--repository-ids', nargs='+', metavar='REPO_ID',
                       help='Repository IDs to filter by')
    
    # Convenience arguments for name-based filtering
    parser.add_argument('--organization-names', nargs='+', metavar='ORG_NAME',
                       help='Organization names to filter by (will lookup IDs)')
    parser.add_argument('--project-names', nargs='+', metavar='PROJECT_NAME',
                       help='Project names to filter by (will lookup IDs)')
    parser.add_argument('--repository-names', nargs='+', metavar='REPO_NAME',
                       help='Repository names to filter by (will lookup IDs)')
    
    # Output arguments
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--summary-only', action='store_true',
                       help='Only show summary, not full data')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose logging')
    parser.add_argument('--config', '-c', default='secret.yaml',
                       help='Path to configuration file (default: secret.yaml)')
    
    # List available resources
    parser.add_argument('--list-projects', action='store_true',
                       help='List available projects and their IDs')
    parser.add_argument('--list-organizations', action='store_true', 
                       help='List available organizations and their IDs')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        fetcher = CycodeAllViolationsFetcher(config_file=args.config)
        
        # Handle listing commands
        if args.list_projects:
            fetcher.setup_session()
            projects = fetcher.get_projects()
            print("\n📁 Available Projects:")
            print("=" * 50)
            for project in projects:
                name = project.get('name', 'N/A')
                project_id = project.get('id', 'N/A')
                description = project.get('description', '')
                print(f"  {name} (ID: {project_id})")
                if description:
                    print(f"    Description: {description[:80]}...")
            return
        
        if args.list_organizations:
            fetcher.setup_session()
            orgs = fetcher.get_organizations()
            print("\n🏢 Available Organizations:")
            print("=" * 50)
            if orgs:
                for org in orgs:
                    name = org.get('name', 'N/A') 
                    org_id = org.get('id', 'N/A')
                    print(f"  {name} (ID: {org_id})")
            else:
                print("  No organizations found or endpoint not available")
            return
        
        # Handle name-based lookups
        organization_ids = args.organization_ids
        project_ids = args.project_ids
        repository_ids = args.repository_ids
        
        if args.organization_names or args.project_names or args.repository_names:
            fetcher.setup_session()
            
            # Lookup organization IDs
            if args.organization_names:
                orgs = fetcher.get_organizations()
                org_lookup = {org.get('name'): org.get('id') for org in orgs if org.get('name')}
                organization_ids = []
                for name in args.organization_names:
                    if name in org_lookup:
                        organization_ids.append(org_lookup[name])
                        logger.info(f"Found organization {name} -> ID: {org_lookup[name]}")
                    else:
                        logger.warning(f"Organization not found: {name}")
            
            # Lookup project/repository IDs  
            if args.project_names or args.repository_names:
                projects = fetcher.get_projects()
                project_lookup = {proj.get('name'): proj.get('id') for proj in projects if proj.get('name')}
                
                if args.project_names:
                    project_ids = []
                    for name in args.project_names:
                        if name in project_lookup:
                            project_ids.append(project_lookup[name])
                            logger.info(f"Found project {name} -> ID: {project_lookup[name]}")
                        else:
                            logger.warning(f"Project not found: {name}")
                
                if args.repository_names:
                    repository_ids = []
                    for name in args.repository_names:
                        if name in project_lookup:
                            repository_ids.append(project_lookup[name])
                            logger.info(f"Found repository {name} -> ID: {project_lookup[name]}")
                        else:
                            logger.warning(f"Repository not found: {name}")
        
        # Fetch all violations
        logger.info("Fetching comprehensive violation data...")
        results = fetcher.fetch_all_violations(
            scan_types=args.scan_types,
            severities=args.severities,
            organization_ids=organization_ids,
            project_ids=project_ids,
            repository_ids=repository_ids
        )
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {args.output}")
        
        # Display summary
        summary = results.get('summary', {})
        print("\n" + "="*60)
        print("📊 COMPREHENSIVE SCA VIOLATIONS SUMMARY")  
        print("="*60)
        
        total_violations = summary.get('total_violations', {})
        print(f"🔀 PR Violations (Unmerged Code):")
        print(f"   Open: {total_violations.get('pr_open', 0)}")
        print(f"   Resolved: {total_violations.get('pr_resolved', 0)}")
        print(f"   Dismissed: {total_violations.get('pr_dismissed', 0)}")
        
        print(f"\n🔧 CLI Violations (Merged Code):")
        cli_filtered = total_violations.get('cli_latest', 0)
        cli_all = total_violations.get('cli_all_scantypes', 0)
        
        if cli_all > cli_filtered:
            print(f"   Filtered (requested scan types): {cli_filtered}")
            print(f"   All scan types: {cli_all}")
            
            # Show CLI breakdown by scan type
            cli_breakdown = summary.get('cli_by_scan_type', {})
            if cli_breakdown:
                print(f"   Breakdown by scan type:")
                for scan_type, count in cli_breakdown.items():
                    print(f"     {scan_type}: {count}")
        else:
            print(f"   Total: {cli_filtered}")
        
        by_severity = summary.get('by_severity', {})
        if by_severity:
            print(f"\n📈 By Severity (PR Violations):")
            for severity, count in by_severity.items():
                print(f"   {severity}: {count}")
        
        by_source = summary.get('by_source', {})
        # Use the higher CLI count if available
        actual_cli_count = cli_all if cli_all > cli_filtered else cli_filtered
        total_all = by_source.get('pull_requests', 0) + actual_cli_count
        print(f"\n🎯 Total Violations Across All Sources: {total_all}")
        print(f"   Pull Requests: {by_source.get('pull_requests', 0)}")
        print(f"   Merged Code: {actual_cli_count}")
        
        if not args.summary_only and not args.output:
            print(f"\n💾 Full data available. Use --output to save complete results.")
    
    except Exception as e:
        logger.error(f"Script failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
