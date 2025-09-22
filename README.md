# Cycode SAST Policy Sync Tool

A GitOps-style tool for managing SAST policies in Cycode using local YAML configuration files.

## Overview

This tool allows you to:
- Define SAST policy states in a local YAML file
- Synchronize policy states between your local configuration and the Cycode platform
- Implement GitOps workflows for policy management
- Track policy changes through version control

## Prerequisites

- Python 3.7 or higher
- Cycode account with API access
- API credentials (Client ID and Client Secret)

## Installation

1. Clone this repository or download the files
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### API Credentials

Set your Cycode API credentials as environment variables:

```bash
export CYCODE_CLIENT_ID="your-client-id"
export CYCODE_CLIENT_SECRET="your-client-secret"
export CYCODE_API_URL="https://api.cycode.com"  # Optional, defaults to this value
```

Alternatively, create a `.env` file in the project directory:

```env
CYCODE_CLIENT_ID=your-client-id
CYCODE_CLIENT_SECRET=your-client-secret
CYCODE_API_URL=https://api.cycode.com
```

### Policy Configuration

Edit the `sast_policies.yaml` file to define your desired policy states:

```yaml
policies:
  - id: "usage-of-dangerous-global-function"
    name: "Usage of dangerous 'global' function"
    category: "SAST"
    subcategory: "Security"
    severity: "Critical"
    enabled: true
    description: "Detects usage of dangerous global functions"

  - id: "unsanitized-user-input-injection"
    name: "Unsanitized user input injection"
    category: "SAST"
    subcategory: "Security"
    severity: "Critical"
    enabled: false
    description: "Identifies potential injection vulnerabilities"
```

## Usage

### Basic Sync

Synchronize policies between local YAML and Cycode platform:

```bash
python cycode_policy_sync.py
```

### Dry Run

Preview changes without applying them:

```bash
python cycode_policy_sync.py --dry-run
```

### Custom Configuration File

Use a different YAML configuration file:

```bash
python cycode_policy_sync.py --config my_policies.yaml
```

### Verbose Output

Enable detailed logging:

```bash
python cycode_policy_sync.py --verbose
```

## GitOps Workflow

### 1. Version Control Setup

Store your configuration in Git:

```bash
git init
git add sast_policies.yaml cycode_policy_sync.py requirements.txt
git commit -m "Initial policy configuration"
```

### 2. CI/CD Integration

Example GitHub Actions workflow (`.github/workflows/sync-policies.yml`):

```yaml
name: Sync Cycode SAST Policies

on:
  push:
    branches: [ main ]
    paths: [ 'sast_policies.yaml' ]

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Sync policies
      env:
        CYCODE_CLIENT_ID: ${{ secrets.CYCODE_CLIENT_ID }}
        CYCODE_CLIENT_SECRET: ${{ secrets.CYCODE_CLIENT_SECRET }}
      run: |
        python cycode_policy_sync.py
```

### 3. Making Policy Changes

1. Edit `sast_policies.yaml` to change policy states
2. Commit and push changes:
   ```bash
   git add sast_policies.yaml
   git commit -m "Disable XSS detection policy"
   git push origin main
   ```
3. The CI/CD pipeline will automatically sync the changes to Cycode

## API Documentation

This tool is built using the Cycode API documented at [https://docs.cycode.com/apidocs](https://docs.cycode.com/apidocs).

### Key Endpoints Used

- **Authentication**: `POST /auth/token` - Obtain access token
- **List Policies**: `GET /v1/policies/sast` - Retrieve current SAST policies
- **Update Policy**: `PATCH /v1/policies/sast/{policy_id}` - Update policy state

> **Note**: The exact API endpoints may vary. Refer to the official Cycode API documentation for the most current endpoint specifications.

## Logging

The tool generates logs in two places:
- Console output (stdout)
- Log file: `cycode_sync.log`

Log levels:
- `INFO`: General operation information
- `WARNING`: Non-critical issues (e.g., policy not found)
- `ERROR`: Critical errors that prevent operation

## Error Handling

The tool includes comprehensive error handling for:
- Authentication failures
- Network connectivity issues
- API rate limiting
- Invalid YAML configuration
- Missing policies

## Security Considerations

- Store API credentials securely (environment variables or secret management)
- Use HTTPS for all API communications
- Rotate API credentials regularly
- Limit API permissions to minimum required scope

## Troubleshooting

### Authentication Issues
- Verify your Client ID and Client Secret are correct
- Check that your Cycode account has API access enabled
- Ensure environment variables are properly set

### Policy Not Found Warnings
- Verify policy IDs in your YAML match those in Cycode
- Check that policies exist in your Cycode organization
- Review the Cycode web interface to confirm policy names and IDs

### Network Issues
- Check internet connectivity
- Verify Cycode API endpoint is accessible
- Consider proxy settings if behind corporate firewall

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This tool is provided as-is for educational and operational purposes. Ensure compliance with your organization's security policies when using API credentials.

## Support

For issues related to:
- **This tool**: Create an issue in this repository
- **Cycode API**: Contact Cycode support
- **Policy configuration**: Refer to Cycode documentation

---

**Important**: This is a foundational implementation. Always test in a non-production environment first and verify API endpoints match the current Cycode API documentation at [https://docs.cycode.com/apidocs](https://docs.cycode.com/apidocs).

