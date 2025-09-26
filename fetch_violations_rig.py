#!/usr/bin/env python3
"""
Cycode RIG (Risk Information Graph) Violation Fetcher

This script uses Cycode's RIG GraphQL-like queries to fetch detailed violation information
that was previously unavailable through the standard API endpoints.

Features:
- Detailed SCA vulnerability data (package names, versions, CVSS scores)
- SAST violation details (file paths, line numbers, rule names)
- Secrets detection information (secret types, locations)
- Comprehensive filtering and reporting capabilities
"""

import sys
import os
import json
import yaml
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add the download-cycode-report directory to the path
sys.path.append('download-cycode-report')

import cycode_lib.cycode_token as tok
import cycode_lib.rig_functions as rig


class CycodeRIGFetcher:
    """Main class for fetching violations using Cycode's RIG queries"""
    
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
    
    def load_rig_query(self, query_file: str) -> Dict[str, Any]:
        """Load RIG query from JSON file"""
        try:
            with open(query_file, 'r') as f:
                query = json.load(f)
            print(f"✅ Loaded RIG query from: {query_file}")
            return query
        except FileNotFoundError:
            print(f"❌ Query file not found: {query_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in query file: {e}")
            sys.exit(1)
    
    def execute_rig_query(self, query: Dict[str, Any], output_format: str = 'JSON') -> bytes:
        """Execute RIG query and return results"""
        try:
            print(f"🚀 Executing RIG query...")
            execution_id = rig.execute_rig_query(
                raw_query=query,
                output_format=output_format,
                cycode_api_url=self.cycode_api_url,
                token=self.token
            )
            print(f"✅ Query execution started! Execution ID: {execution_id}")
            
            # Download results (this will poll until complete)
            print("📥 Downloading results...")
            results = rig.download_rig_results(
                execution_id=execution_id,
                cycode_api_url=self.cycode_api_url,
                token=self.token
            )
            
            print(f"✅ Results downloaded successfully! Size: {len(results)} bytes")
            return results
            
        except Exception as e:
            print(f"❌ Error executing RIG query: {e}")
            raise
    
    def parse_results(self, results: bytes) -> List[Dict[str, Any]]:
        """Parse JSON results and return structured data"""
        try:
            data = json.loads(results.decode('utf-8'))
            if isinstance(data, list):
                return data
            else:
                print(f"⚠️ Unexpected data format: {type(data)}")
                return [data] if data else []
        except json.JSONDecodeError as e:
            print(f"❌ Error parsing JSON results: {e}")
            return []
    
    def analyze_violations(self, violations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze violations and generate summary statistics"""
        if not violations:
            return {"total": 0, "by_category": {}, "by_severity": {}, "by_repository": {}}
        
        analysis = {
            "total": len(violations),
            "by_category": {},
            "by_severity": {},
            "by_repository": {},
            "by_policy": {},
            "severity_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        }
        
        for violation in violations:
            # Category analysis
            category = violation.get('detection_category', 'Unknown')
            analysis["by_category"][category] = analysis["by_category"].get(category, 0) + 1
            
            # Severity analysis
            severity = violation.get('detection_severity', 'Unknown')
            analysis["by_severity"][severity] = analysis["by_severity"].get(severity, 0) + 1
            
            # Repository analysis
            repo = violation.get('detection_detection_details.repository_name', 'Unknown')
            analysis["by_repository"][repo] = analysis["by_repository"].get(repo, 0) + 1
            
            # Policy analysis
            policy = violation.get('detection_source_policy_name', 'Unknown')
            analysis["by_policy"][policy] = analysis["by_policy"].get(policy, 0) + 1
            
            # Severity breakdown for summary
            if severity in analysis["severity_breakdown"]:
                analysis["severity_breakdown"][severity] += 1
        
        return analysis
    
    def print_summary(self, analysis: Dict[str, Any]):
        """Print formatted summary of violations"""
        print("\n" + "="*80)
        print("📊 CYCODE RIG VIOLATIONS SUMMARY")
        print("="*80)
        
        print(f"🔢 Total Violations: {analysis['total']}")
        
        if analysis['by_category']:
            print(f"\n📂 By Category:")
            for category, count in sorted(analysis['by_category'].items()):
                print(f"   {category}: {count}")
        
        if analysis['by_severity']:
            print(f"\n⚠️ By Severity:")
            for severity, count in sorted(analysis['by_severity'].items()):
                print(f"   {severity}: {count}")
        
        if analysis['by_repository']:
            print(f"\n🏗️ By Repository:")
            for repo, count in sorted(analysis['by_repository'].items()):
                print(f"   {repo}: {count}")
        
        if analysis['by_policy']:
            print(f"\n📋 By Policy:")
            for policy, count in sorted(analysis['by_policy'].items()):
                print(f"   {policy}: {count}")
        
        print("="*80)
    
    def save_results(self, violations: List[Dict[str, Any]], output_file: str):
        """Save violations to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(violations, f, indent=2)
            print(f"✅ Results saved to: {output_file}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")
    
    def fetch_violations(self, query_file: str, output_file: str = None, output_format: str = 'JSON'):
        """Main method to fetch violations using RIG queries"""
        print(f"🔍 Starting RIG violation fetch...")
        print(f"   Query file: {query_file}")
        print(f"   Output format: {output_format}")
        
        # Authenticate
        if not self.authenticate():
            return False
        
        # Load query
        query = self.load_rig_query(query_file)
        
        # Execute query
        try:
            results = self.execute_rig_query(query, output_format)
        except Exception as e:
            print(f"❌ Failed to execute query: {e}")
            return False
        
        # Parse results
        violations = self.parse_results(results)
        print(f"📊 Parsed {len(violations)} violations")
        
        # Analyze violations
        analysis = self.analyze_violations(violations)
        self.print_summary(analysis)
        
        # Save results
        if output_file:
            self.save_results(violations, output_file)
        
        return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Fetch Cycode violations using RIG queries')
    parser.add_argument('-q', '--query-file', required=True, help='RIG query JSON file')
    parser.add_argument('-o', '--output-file', help='Output JSON file')
    parser.add_argument('-f', '--format', default='JSON', choices=['JSON', 'CSV'], help='Output format')
    parser.add_argument('-c', '--config', default='secret.yaml', help='Config file with credentials')
    
    args = parser.parse_args()
    
    # Generate default output filename if not provided
    if not args.output_file:
        query_name = os.path.splitext(os.path.basename(args.query_file))[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output_file = f"{query_name}_results_{timestamp}.json"
    
    # Create fetcher and run
    fetcher = CycodeRIGFetcher(config_file=args.config)
    success = fetcher.fetch_violations(
        query_file=args.query_file,
        output_file=args.output_file,
        output_format=args.format
    )
    
    if success:
        print(f"\n✅ RIG violation fetch completed successfully!")
        print(f"📁 Results saved to: {args.output_file}")
    else:
        print(f"\n❌ RIG violation fetch failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
