#!/usr/bin/env python3
"""
Cycode Violations Fetcher

This script attempts to fetch open violations from the Cycode API,
specifically targeting SCA violations for testing validation.
"""

import requests
import json
import os
import logging
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CycodeViolationsFetcher:
    """Fetches violations from Cycode API"""
    
    def __init__(self, api_url: str = None, client_id: str = None, client_secret: str = None, config_file: str = None):
        # Load from config file first, then environment variables, then parameters
        config = self._load_config(config_file)
        
        self.api_url = api_url or config.get("api_url") or os.getenv("CYCODE_API_URL", "https://api.cycode.com")
        self.client_id = client_id or config.get("client_id") or os.getenv("CYCODE_CLIENT_ID")
        self.client_secret = client_secret or config.get("client_secret") or os.getenv("CYCODE_CLIENT_SECRET")
        self.access_token = None
        self.session = requests.Session()
        
        if not self.client_id or not self.client_secret:
            logger.error("Cycode API credentials must be provided via config file, environment variables, or parameters")
            logger.error("Config file should contain: cycode.client_id and cycode.client_secret")
            raise ValueError("Missing Cycode API credentials")
    
    def _load_config(self, config_file: str = None) -> Dict[str, str]:
        """Load configuration from YAML file"""
        if not config_file:
            # Try default locations
            possible_files = [
                "secret.yaml",
                "secrets.yaml", 
                "config.yaml",
                "cycode.yaml"
            ]
            
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
                
            # Extract cycode section
            cycode_config = config.get('cycode', {})
            logger.info(f"Loaded configuration from {config_file}")
            return cycode_config
            
        except Exception as e:
            logger.warning(f"Failed to load config from {config_file}: {e}")
            return {}
    
    def get_access_token(self) -> str:
        """Get JWT access token from Cycode API using the correct method from the blog post"""
        logger.info("Attempting to get JWT token...")
        
        # Use the correct Cycode authentication endpoint from the blog post
        token_url = f"{self.api_url}/api/v1/auth/api-token"
        
        auth_headers = {
            "Content-Type": "application/json", 
            "Accept": "application/json"
        }
        
        # Use the exact payload format from the blog post
        payload = {
            "clientId": self.client_id,
            "secret": self.client_secret
        }
        
        try:
            logger.debug(f"Requesting JWT token from: {token_url}")
            response = requests.post(token_url, json=payload, headers=auth_headers, timeout=180)
            
            logger.debug(f"Token request response: {response.status_code}")
            
            if response.status_code == 200:
                token_data = response.json()
                jwt_token = token_data.get('token')
                
                if jwt_token:
                    logger.info("Successfully obtained JWT token from Cycode API")
                    self.access_token = f"Bearer {jwt_token}"
                    return self.access_token
                else:
                    logger.error("JWT token not found in response")
                    logger.debug(f"Response: {token_data}")
            else:
                logger.error(f"Failed to get JWT token: {response.status_code}")
                logger.debug(f"Response text: {response.text}")
                
        except Exception as e:
            logger.error(f"Exception during JWT token request: {e}")
        
        # If JWT token fails, return None to indicate failure
        logger.error("Failed to obtain JWT token")
        return None
    
    def setup_session(self):
        """Setup session with authentication headers"""
        if not self.access_token:
            self.access_token = self.get_access_token()
        
        if not self.access_token:
            raise ValueError("Failed to obtain access token")
        
        self.session.headers.update({
            "Authorization": self.access_token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
    
    def discover_violations_endpoints(self) -> List[str]:
        """Discover potential violations endpoints"""
        potential_endpoints = [
            # Most likely violations endpoints
            "/v4/violations",
            "/v4/scan-results", 
            "/v4/detections",
            "/v4/findings",
            
            # Pull request specific
            "/v4/pull-requests/violations",
            "/v4/pull-requests/scan-results",
            "/v4/scans/pull-requests/violations",
            
            # Repository specific  
            "/v4/repositories/violations",
            "/v4/repositories/scan-results",
            
            # Organization level
            "/v4/organizations/violations",
            "/v4/organizations/scan-results",
            
            # Generic scans
            "/v4/scans/violations",
            "/v4/scans/results",
            "/v4/scans/detections"
        ]
        
        logger.info("Discovering violations endpoints...")
        available_endpoints = []
        
        for endpoint in potential_endpoints:
            try:
                url = f"{self.api_url}{endpoint}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    logger.info(f"✅ Found working endpoint: {endpoint}")
                    available_endpoints.append(endpoint)
                elif response.status_code == 401:
                    logger.warning(f"🔐 Authentication failed for: {endpoint}")
                elif response.status_code == 403:
                    logger.warning(f"🚫 Access forbidden for: {endpoint}")
                elif response.status_code == 404:
                    logger.debug(f"❌ Not found: {endpoint}")
                else:
                    logger.info(f"🤔 Response {response.status_code} for: {endpoint}")
                    
            except Exception as e:
                logger.debug(f"Error testing {endpoint}: {e}")
        
        return available_endpoints
    
    def fetch_violations(self, 
                        scan_types: List[str] = None,
                        severities: List[str] = None, 
                        status: List[str] = None,
                        repository_ids: List[str] = None,
                        limit: int = 100) -> Dict[str, Any]:
        """Fetch violations with filtering"""
        
        self.setup_session()
        
        # Discover available endpoints
        available_endpoints = self.discover_violations_endpoints()
        
        if not available_endpoints:
            logger.error("No violations endpoints found!")
            return {"error": "No accessible violations endpoints"}
        
        results = {}
        
        for endpoint in available_endpoints:
            logger.info(f"Fetching violations from: {endpoint}")
            
            # Build query parameters
            params = {}
            if scan_types:
                params['scan_types'] = scan_types
            if severities:
                params['severities'] = severities  
            if status:
                params['status'] = status
            if repository_ids:
                params['repository_ids'] = repository_ids
            if limit:
                params['limit'] = limit
            
            # Add time range (last 30 days)
            params['from'] = (datetime.now() - timedelta(days=30)).isoformat()
            params['to'] = datetime.now().isoformat()
            
            try:
                url = f"{self.api_url}{endpoint}"
                response = self.session.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    results[endpoint] = {
                        "status": "success",
                        "data": data,
                        "count": len(data) if isinstance(data, list) else "unknown"
                    }
                    logger.info(f"✅ Successfully fetched from {endpoint}")
                    
                    # Log sample of data structure
                    if isinstance(data, list) and data:
                        logger.info(f"Sample record keys: {list(data[0].keys()) if isinstance(data[0], dict) else 'N/A'}")
                    elif isinstance(data, dict):
                        logger.info(f"Response keys: {list(data.keys())}")
                        
                else:
                    results[endpoint] = {
                        "status": "error", 
                        "status_code": response.status_code,
                        "error": response.text[:200]
                    }
                    logger.warning(f"❌ Failed to fetch from {endpoint}: {response.status_code}")
                    
            except Exception as e:
                results[endpoint] = {
                    "status": "exception",
                    "error": str(e)
                }
                logger.error(f"Exception fetching from {endpoint}: {e}")
        
        return results
    
    def fetch_sca_violations(self, repository_names: List[str] = None) -> Dict[str, Any]:
        """Specifically fetch SCA violations"""
        logger.info("Fetching SCA violations...")
        
        # Try to get repository IDs if names provided
        repository_ids = None
        if repository_names:
            repository_ids = self.get_repository_ids(repository_names)
        
        return self.fetch_violations(
            scan_types=["SCA"],
            severities=["Critical", "High", "Medium", "Low"],
            status=["Open"],
            repository_ids=repository_ids,
            limit=100
        )
    
    def get_repository_ids(self, repository_names: List[str]) -> List[str]:
        """Get repository IDs from repository names"""
        logger.info(f"Looking up repository IDs for: {repository_names}")
        
        try:
            # Try common repositories endpoint
            url = f"{self.api_url}/v4/repositories"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                repos = response.json()
                repo_ids = []
                
                if isinstance(repos, list):
                    for repo in repos:
                        if isinstance(repo, dict) and repo.get('name') in repository_names:
                            repo_ids.append(repo.get('id'))
                
                logger.info(f"Found repository IDs: {repo_ids}")
                return repo_ids
            else:
                logger.warning(f"Failed to fetch repositories: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error fetching repository IDs: {e}")
        
        return None

def main():
    """CLI interface for violations fetcher"""
    parser = argparse.ArgumentParser(description='Fetch Cycode violations')
    parser.add_argument('--scan-types', nargs='+', default=['SCA'], 
                       help='Scan types to filter (default: SCA)')
    parser.add_argument('--severities', nargs='+', default=['Critical', 'High'],
                       help='Severities to filter (default: Critical, High)')
    parser.add_argument('--status', nargs='+', default=['Open'],
                       help='Status to filter (default: Open)')
    parser.add_argument('--repositories', nargs='+',
                       help='Repository names to filter')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose logging')
    parser.add_argument('--discover-only', action='store_true',
                       help='Only discover endpoints, don\'t fetch data')
    parser.add_argument('--config', '-c', default='secret.yaml',
                       help='Path to configuration file (default: secret.yaml)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        fetcher = CycodeViolationsFetcher(config_file=args.config)
        
        if args.discover_only:
            fetcher.setup_session()
            endpoints = fetcher.discover_violations_endpoints()
            print(f"\n🔍 Discovered {len(endpoints)} accessible endpoints:")
            for endpoint in endpoints:
                print(f"  ✅ {endpoint}")
            return
        
        # Fetch violations
        if args.repositories:
            logger.info(f"Fetching violations for repositories: {args.repositories}")
            results = fetcher.fetch_sca_violations(args.repositories)
        else:
            logger.info("Fetching violations with filters...")
            results = fetcher.fetch_violations(
                scan_types=args.scan_types,
                severities=args.severities,
                status=args.status,
                repository_ids=None
            )
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {args.output}")
        else:
            print("\n📊 Violations Fetch Results:")
            print("=" * 50)
            for endpoint, result in results.items():
                print(f"\n🔗 {endpoint}:")
                if result.get("status") == "success":
                    count = result.get("count", "unknown")
                    print(f"  ✅ Success - Found {count} records")
                    
                    # Show sample data structure
                    data = result.get("data")
                    if isinstance(data, list) and data:
                        sample = data[0]
                        if isinstance(sample, dict):
                            print(f"  📋 Sample fields: {', '.join(list(sample.keys())[:10])}")
                    elif isinstance(data, dict):
                        print(f"  📋 Response fields: {', '.join(list(data.keys())[:10])}")
                else:
                    print(f"  ❌ {result.get('status', 'Unknown')}: {result.get('error', 'No details')}")
    
    except Exception as e:
        logger.error(f"Script failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
