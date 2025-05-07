# AWS Prowler Shake n' Bake (Validator)

A comprehensive Python script for validating AWS security findings and configurations against all 301 Prowler checks.

## Key Features

- **Combined Functionality**: Merges the capabilities of prowlershake.py and prowlerbake.py into a single powerful tool
- **Complete Coverage**: Supports all 301 Prowler security checks
- **Two Operation Modes**:
  - **Check Mode**: Directly run security validations on your AWS environment
  - **Report Mode**: Verify findings from a Prowler JSON report
- **True Positive Detection**: Automatically classifies findings as true/false positives
- **Resource-Specific Validation**: Target specific resources for validation
- **Command-Line Output Validation**: Uses Prowler CLI for checks that aren't directly implemented

## Prerequisites

- **Python 3.8+**
- **pip** or **conda** for managing packages
- **AWS CLI** configured with named profiles in `~/.aws/credentials` and/or `~/.aws/config`
- **Poetry** for Python dependency management
- **Prowler 3.0.0+** installed via Poetry
- **(Optional)** A Prowler JSON report for report mode

## Installation

1. **Clone or copy** the script to your system:

   ```bash
   git clone <repo_url> prowler-shakenbake
   cd prowler-shakenbake
   ```

2. **Create and activate** an isolated environment:

   **Using venv**

   ```bash
   python3 -m venv myvenv
   source myvenv/bin/activate  # On Windows: myvenv\Scripts\activate
   ```

   **Using conda**

   ```bash
   conda create -n prowler-validator python=3.11
   conda activate prowler-validator
   ```

3. **Install dependencies**:

   ```bash
   # Install required Python packages
   pip install boto3 pandas

   # Install Poetry (if not already installed)
   curl -sSL https://install.python-poetry.org | python3 -

   # Install Prowler via Poetry
   poetry init -n
   poetry add prowler
   
   # Or if you already have a poetry.toml/pyproject.toml, run:
   poetry install
   ```

4. **Verify Prowler installation**:

   ```bash
   # Verify Prowler installation and version
   poetry run prowler --version
   
   # Expected output should show at least version 3.0.0
   ```

## Usage

The script has three main modes of operation:

### 1. Check Mode (Direct Validation)

```bash
python prowler_shakenbake.py check [options]
```

**Options**:
- `--profile PROFILE` - Specific AWS profile to check (default: all profiles)
- `--region REGION` - AWS region to use (default: us-east-1)
- `--check CHECK [CHECK ...]` - Specific checks to run (default: all implemented)
- `--resource-id RESOURCE_ID` - Specific resource ID to check (default: all resources)
- `--output OUTPUT` - Output CSV path (default: aws_validation_results.csv)

**Examples**:

```bash
# Run all checks on all profiles
python prowler_shakenbake.py check

# Run specific checks on a profile
python prowler_shakenbake.py check --profile myprofile --check "Ensure IAM Roles do not have AdministratorAccess policy attached" "Check S3 Account Level Public Access Block"

# Check a specific resource
python prowler_shakenbake.py check --profile myprofile --check "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to any port." --resource-id sg-01234567890abcdef
```

### 2. Report Mode (Validate Prowler Findings)

```bash
python prowler_shakenbake.py report [options]
```

**Options**:
- `--report REPORT` - Path to Prowler JSON report (required)
- `--severity SEVERITY [SEVERITY ...]` - Severities to include (default: critical high moderate low)
- `--output OUTPUT` - Output CSV path (default: aws_validation_results.csv)

**Examples**:

```bash
# Validate all findings in a report
python prowler_shakenbake.py report --report prowler_report.json

# Validate only critical and high findings
python prowler_shakenbake.py report --report prowler_report.json --severity critical high
```

### 3. List Available Checks

```bash
python prowler_shakenbake.py list [options]
```

**Options**:
- `--implemented` - Show only implemented checks (those not requiring Prowler CLI)

## Output CSV Format

The script generates a CSV file with the following columns:

- **profile**: AWS CLI profile name
- **account_id**: AWS Account ID (prefixed with `'` to force Excel text format)
- **region**: AWS region used
- **check_title**: Name of the validated check
- **resource_id**: Identifier of the AWS resource
- **status**: `PASS` or `FAIL` based on the AWS validation
- **details**: JSON detail or error message
- **true_positive**: `TRUE` if real finding, `FALSE` if empty or permission error, blank if PASS

## Validator Types

The script uses different types of validators to check security configurations:

1. **Direct Validators**: Implemented in Python using boto3, these validators don't require the Prowler CLI
2. **Prowler CLI Validators**: For checks not directly implemented, the script calls Prowler CLI and parses the results
3. **Stub Validators**: For checks that are not yet implemented, placeholder functions that return "not implemented"

## Configuration Options

You can adjust the following constants at the top of the script:

- `OUTPUT_CSV`: Default CSV output path
- `ACM_EXPIRY_DAYS`: Number of days to consider an ACM certificate as "soon to expire"
- `CW_RETENTION_DAYS`: Maximum allowed CloudWatch log retention days
- `DEFAULT_REGION`: Fallback region if not specified
- `EC2_OLD_INSTANCE_DAYS`: Days threshold for considering an EC2 instance "old"
- `PROWLER_MIN_VERSION`: Minimum required Prowler version

## Extending the Script

To add support for new checks or modify existing ones:

1. Add a new validator function following the signature: `fn(session, resource_id, region) -> {"status":bool,"details":...}`
2. Add the validator to the `VALIDATORS` dictionary, mapping the check title to the function
3. If using Prowler CLI, add the check title to Prowler ID mapping in the `PROWLER_CHECK_IDS` dictionary

## Troubleshooting

- **Permission Errors**: Ensure each profile has read access to the AWS services being checked.
- **Region Issues**: If encountering region errors, try specifying a region with `--region`.
- **Prowler Not Found**: Ensure Prowler is installed via Poetry and the command `poetry run prowler` works.
- **Missing Checks**: Check the list of available checks with `python prowler_shakenbake.py list`.
- **Resource-Specific Issues**: If a specific resource check fails, try running without `--resource-id` to check all resources.
- **Poetry Issues**: Make sure Poetry is properly installed and configured in your environment.
- **Dependency Problems**: If you encounter import errors, verify that all dependencies are installed with `pip list | grep boto3` and `pip list | grep pandas`.
- **AWS CLI Configuration**: Ensure your AWS profiles are properly configured in the AWS credentials file.


## License

This project is licensed under the MIT License.
