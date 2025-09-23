#!/usr/bin/env python3
"""
Cycode SAST Policy Synchronization Tool

This script provides a GitOps-style approach to managing SAST policies in Cycode.
It reads policy configurations from a local YAML file and synchronizes them with
the remote Cycode platform.

Note: This is a foundational implementation. The actual API endpoints and authentication
methods will need to be updated based on Cycode's official API documentation.
"""

import os
import sys
import yaml
import requests
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cycode_sync.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class PolicyState:
    """Represents the state of a SAST policy"""
    id: str
    name: str
    category: str
    subcategory: str
    severity: str
    enabled: bool
    description: Optional[str] = None

class CycodeAPIClient:
    """
    Client for interacting with the Cycode API
    
    Note: This implementation is based on common REST API patterns.
    The actual endpoints and authentication methods need to be updated
    based on Cycode's official API documentation.
    """
    
    def __init__(self, base_url: str = None, client_id: str = None, client_secret: str = None):
        # These values should be updated based on actual Cycode API documentation
        self.base_url = base_url or os.getenv('CYCODE_API_URL', 'https://api.cycode.com')
        self.client_id = client_id or os.getenv('CYCODE_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('CYCODE_CLIENT_SECRET')
        
        if not self.client_id or not self.client_secret:
            raise ValueError("Cycode client credentials are required. Set CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET environment variables.")
        
        self.session = requests.Session()
        self.access_token = None
        
    def authenticate(self) -> bool:
        """
        Authenticate with Cycode API
        
        Note: This authentication method is hypothetical and should be updated
        based on Cycode's actual authentication flow.
        """
        try:
            auth_url = f"{self.base_url}/auth/token"
            auth_data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials'
            }
            
            response = self.session.post(auth_url, data=auth_data)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            
            if self.access_token:
                self.session.headers.update({
                    'Authorization': f'Bearer {self.access_token}',
                    'Content-Type': 'application/json'
                })
                logger.info("Successfully authenticated with Cycode API")
                return True
            else:
                logger.error("Failed to obtain access token")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            return False
    
    def get_sast_policies(self) -> List[PolicyState]:
        """
        Retrieve current SAST policies from Cycode
        
        Note: This endpoint is hypothetical and should be updated based on
        Cycode's actual API documentation.
        """
        try:
            policies_url = f"{self.base_url}/v1/policies/sast"
            response = self.session.get(policies_url)
            response.raise_for_status()
            
            policies_data = response.json()
            policies = []
            
            # Parse the response based on actual API structure
            for policy_data in policies_data.get('policies', []):
                policy = PolicyState(
                    id=policy_data.get('id'),
                    name=policy_data.get('name'),
                    category=policy_data.get('category', 'SAST'),
                    subcategory=policy_data.get('subcategory', 'Security'),
                    severity=policy_data.get('severity', 'Medium'),
                    enabled=policy_data.get('enabled', False),
                    description=policy_data.get('description')
                )
                policies.append(policy)
            
            logger.info(f"Retrieved {len(policies)} SAST policies from Cycode")
            return policies
            
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve SAST policies: {e}")
            return []
    
    def update_policy_state(self, policy_id: str, enabled: bool) -> bool:
        """
        Update the enabled/disabled state of a specific policy
        
        Note: This endpoint is hypothetical and should be updated based on
        Cycode's actual API documentation.
        """
        try:
            policy_url = f"{self.base_url}/v1/policies/sast/{policy_id}"
            update_data = {'enabled': enabled}
            
            response = self.session.patch(policy_url, json=update_data)
            response.raise_for_status()
            
            action = "enabled" if enabled else "disabled"
            logger.info(f"Successfully {action} policy {policy_id}")
            return True
            
        except requests.RequestException as e:
            logger.error(f"Failed to update policy {policy_id}: {e}")
            return False

class PolicySyncManager:
    """Manages synchronization between local YAML configuration and Cycode platform"""
    
    def __init__(self, config_file: str = 'sast_policies.yaml'):
        self.config_file = config_file
        self.api_client = None
    
    def load_local_config(self) -> List[PolicyState]:
        """Load policy configuration from local YAML file"""
        try:
            with open(self.config_file, 'r') as file:
                config = yaml.safe_load(file)
            
            policies = []
            for policy_data in config.get('policies', []):
                policy = PolicyState(
                    id=policy_data.get('id'),
                    name=policy_data.get('name'),
                    category=policy_data.get('category', 'SAST'),
                    subcategory=policy_data.get('subcategory', 'Security'),
                    severity=policy_data.get('severity', 'Medium'),
                    enabled=policy_data.get('enabled', False),
                    description=policy_data.get('description')
                )
                policies.append(policy)
            
            logger.info(f"Loaded {len(policies)} policies from {self.config_file}")
            return policies
            
        except FileNotFoundError:
            logger.error(f"Configuration file {self.config_file} not found")
            return []
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML configuration: {e}")
            return []
    
    def initialize_api_client(self) -> bool:
        """Initialize and authenticate the API client"""
        try:
            self.api_client = CycodeAPIClient()
            return self.api_client.authenticate()
        except ValueError as e:
            logger.error(f"Failed to initialize API client: {e}")
            return False
    
    def sync_policies(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Synchronize local policy configuration with Cycode platform
        
        Args:
            dry_run: If True, only show what would be changed without making actual changes
        
        Returns:
            Dictionary containing sync results
        """
        if not self.initialize_api_client():
            return {'success': False, 'error': 'Failed to authenticate with Cycode API'}
        
        local_policies = self.load_local_config()
        if not local_policies:
            return {'success': False, 'error': 'No local policies found'}
        
        # Get current state from Cycode
        remote_policies = self.api_client.get_sast_policies()
        remote_policy_map = {p.id: p for p in remote_policies}
        
        # Compare and identify changes needed
        changes_needed = []
        for local_policy in local_policies:
            remote_policy = remote_policy_map.get(local_policy.id)
            
            if not remote_policy:
                logger.warning(f"Policy {local_policy.id} not found in remote Cycode platform")
                continue
            
            if remote_policy.enabled != local_policy.enabled:
                changes_needed.append({
                    'policy_id': local_policy.id,
                    'policy_name': local_policy.name,
                    'current_state': remote_policy.enabled,
                    'desired_state': local_policy.enabled,
                    'action': 'enable' if local_policy.enabled else 'disable'
                })
        
        # Log what changes are needed
        if changes_needed:
            logger.info(f"Found {len(changes_needed)} policies that need to be updated:")
            for change in changes_needed:
                logger.info(f"  - {change['policy_name']}: {change['action']}")
        else:
            logger.info("All policies are already in sync")
            return {'success': True, 'changes': [], 'message': 'No changes needed'}
        
        # Apply changes if not in dry-run mode
        if not dry_run:
            successful_changes = []
            failed_changes = []
            
            for change in changes_needed:
                success = self.api_client.update_policy_state(
                    change['policy_id'], 
                    change['desired_state']
                )
                
                if success:
                    successful_changes.append(change)
                else:
                    failed_changes.append(change)
            
            return {
                'success': len(failed_changes) == 0,
                'changes': successful_changes,
                'failed_changes': failed_changes,
                'total_changes': len(changes_needed)
            }
        else:
            return {
                'success': True,
                'changes': changes_needed,
                'dry_run': True,
                'message': 'Dry run completed - no changes were made'
            }

def main():
    """Main entry point for the sync tool"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Sync SAST policies between local YAML and Cycode platform')
    parser.add_argument('--config', '-c', default='sast_policies.yaml', 
                       help='Path to YAML configuration file (default: sast_policies.yaml)')
    parser.add_argument('--dry-run', '-d', action='store_true',
                       help='Show what would be changed without making actual changes')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize sync manager
    sync_manager = PolicySyncManager(args.config)
    
    # Perform synchronization
    logger.info("Starting SAST policy synchronization...")
    result = sync_manager.sync_policies(dry_run=args.dry_run)
    
    if result['success']:
        if args.dry_run:
            logger.info("Dry run completed successfully")
            if result['changes']:
                print(f"\nChanges that would be made:")
                for change in result['changes']:
                    print(f"  - {change['policy_name']}: {change['action']}")
        else:
            logger.info("Synchronization completed successfully")
            if result.get('changes'):
                print(f"\nSuccessfully updated {len(result['changes'])} policies")
            if result.get('failed_changes'):
                print(f"Failed to update {len(result['failed_changes'])} policies")
    else:
        logger.error(f"Synchronization failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)

if __name__ == '__main__':
    main()


