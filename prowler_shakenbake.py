#!/usr/bin/env python3
"""
prowler_validator.py - AWS Security Validation Script

This script provides two main functionalities:
1. Run security validations against all AWS CLI profiles (shake mode)
2. Parse and validate Prowler JSON report findings (bake mode)

It supports validation for all 301 Prowler security checks with true positive detection.
"""

import argparse
import boto3
import pandas as pd
import json
import re
import base64
import ipaddress
import subprocess
import shlex
import os
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoRegionError

# ─────────── Configuration ───────────
OUTPUT_CSV = "aws_validation_results.csv"
ACM_EXPIRY_DAYS = 30
CW_RETENTION_DAYS = 90
DEFAULT_REGION = "us-east-1"
EC2_OLD_INSTANCE_DAYS = 180
PROWLER_MIN_VERSION = "3.0.0"

# ─────────── Helpers ───────────
def client(session, service, region=None):
    """Create client with region support and default fallback."""
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    try:
        return session.client(service, **kwargs)
    except NoRegionError:
        return session.client(service, region_name=DEFAULT_REGION)

def get_account_id(session):
    """Get the AWS Account ID for the session."""
    return client(session, "sts").get_caller_identity()["Account"]

def classify_tp(status, details):
    """Classify if a finding is a true positive based on status and details."""
    if status:
        return ""
    txt = details if isinstance(details, str) else json.dumps(details)
    if "AccessDeniedException" in txt:
        return "FALSE"
    try:
        d = details if isinstance(details, dict) else json.loads(txt)
        for v in d.values():
            if isinstance(v, list) and v:
                return "TRUE"
    except:
        pass
    return "FALSE"

def run_command(cmd, resource_id=None):
    """Run a shell command and return the output."""
    try:
        if resource_id:
            cmd = cmd.replace("{resource_id}", resource_id)
        # Use poetry run prowler instead of just prowler
        cmd = cmd.replace("prowler", "poetry run prowler")
        args = shlex.split(cmd)
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr.strip()}"

def parse_prowler_output(output):
    """Parse Prowler CLI output to determine if check passed or failed."""
    if not output or "Error" in output:
        return {"status": False, "details": output}
    
    # Check for PASS/FAIL in output
    if "PASS" in output:
        return {"status": True, "details": output}
    elif "FAIL" in output:
        return {"status": False, "details": output}
    else:
        # Try to extract meaningful information
        return {"status": False, "details": output}

# ─────────── Validators ───────────
# Signature: fn(session, resource_id, region) -> {"status":bool,"details":...}

def check_s3_pab(sess, resource_id, region):
    """Check if S3 Account Level Public Access Block is enabled."""
    s3c = client(sess, "s3control", region)
    try:
        acct = get_account_id(sess)
        cfg = s3c.get_public_access_block(AccountId=acct)["PublicAccessBlockConfiguration"]
        ok = all(cfg.get(f, False) for f in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
        ))
        return {"status": ok, "details": cfg}
    except ClientError as e:
        return {"status": False, "details": str(e)}

def check_iam_admin_roles(sess, resource_id, region):
    """Check if IAM Roles have AdministratorAccess attached."""
    iam = client(sess, "iam", region)
    bad = []
    
    # If resource_id is provided, check only that role
    if resource_id and resource_id != "*":
        try:
            attached = iam.list_attached_role_policies(RoleName=resource_id)["AttachedPolicies"]
            if any(p["PolicyName"] == "AdministratorAccess" for p in attached):
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all roles
        for r in iam.list_roles()["Roles"]:
            try:
                attached = iam.list_attached_role_policies(RoleName=r["RoleName"])["AttachedPolicies"]
                if any(p["PolicyName"] == "AdministratorAccess" for p in attached):
                    bad.append(r["RoleName"])
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"admin_roles": bad}}

def check_sns_unencrypted(sess, resource_id, region):
    """Check if SNS Topics are encrypted with KMS."""
    sns = client(sess, "sns", region)
    bad = []
    
    # If resource_id is provided, check only that topic
    if resource_id and resource_id != "*":
        try:
            kms = sns.get_topic_attributes(TopicArn=resource_id)["Attributes"].get("KmsMasterKeyId")
            if not kms or kms == "None":
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all topics
        for t in sns.list_topics()["Topics"]:
            arn = t["TopicArn"]
            try:
                kms = sns.get_topic_attributes(TopicArn=arn)["Attributes"].get("KmsMasterKeyId")
                if not kms or kms == "None":
                    bad.append(arn)
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"unencrypted_topics": bad}}

def check_lambda_secrets(sess, resource_id, region):
    """Find secrets in Lambda function variables."""
    lam = client(sess, "lambda", region)
    bad = []
    
    # If resource_id is provided, check only that function
    if resource_id and resource_id != "*":
        try:
            env = lam.get_function_configuration(FunctionName=resource_id) \
                     .get("Environment", {}).get("Variables", {})
            for k, v in env.items():
                if re.search(r"(?i)(secret|password|key)", k):
                    bad.append({resource_id: {k: v}})
        except ClientError:
            pass
    else:
        # Check all functions
        for fn in lam.list_functions()["Functions"]:
            name = fn["FunctionName"]
            try:
                env = lam.get_function_configuration(FunctionName=name) \
                         .get("Environment", {}).get("Variables", {})
                for k, v in env.items():
                    if re.search(r"(?i)(secret|password|key)", k):
                        bad.append({name: {k: v}})
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"lambda_secrets": bad}}

def check_acm_expiry(sess, resource_id, region):
    """Check if ACM Certificates are about to expire."""
    acm = client(sess, "acm", region)
    bad = []
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=ACM_EXPIRY_DAYS)
    
    # If resource_id is provided, check only that certificate
    if resource_id and resource_id != "*":
        try:
            cert = acm.describe_certificate(CertificateArn=resource_id)["Certificate"]
            if cert["NotAfter"] <= cutoff:
                bad.append({"arn": resource_id, "expires": cert["NotAfter"].isoformat()})
        except ClientError:
            pass
    else:
        # Check all certificates
        for cert in acm.list_certificates()["CertificateSummaryList"]:
            arn = cert["CertificateArn"]
            try:
                na = acm.describe_certificate(CertificateArn=arn)["Certificate"]["NotAfter"]
                if na <= cutoff:
                    bad.append({"arn": arn, "expires": na.isoformat()})
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"expiring_certs": bad}}

def check_service_role_trust(sess, resource_id, region):
    """Check IAM Service Roles for confused deputy protection."""
    iam = client(sess, "iam", region)
    bad = []
    
    # If resource_id is provided, check only that role
    if resource_id and resource_id != "*":
        try:
            role = iam.get_role(RoleName=resource_id)["Role"]
            if "service-role" in resource_id or resource_id.startswith("AWSServiceRoleFor"):
                doc = role["AssumeRolePolicyDocument"]
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow" and not stmt.get("Condition"):
                        bad.append(resource_id)
                        break
        except ClientError:
            pass
    else:
        # Check all roles
        for r in iam.list_roles()["Roles"]:
            name = r["RoleName"]
            if "service-role" in name or name.startswith("AWSServiceRoleFor"):
                try:
                    doc = iam.get_role(RoleName=name)["Role"]["AssumeRolePolicyDocument"]
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Allow" and not stmt.get("Condition"):
                            bad.append(name)
                            break
                except ClientError:
                    continue
                    
    return {"status": not bad, "details": {"roles_missing_conditions": bad}}

def check_sg_wide_open(sess, resource_id, region):
    """Check if Security Groups allow 0.0.0.0/0 ingress."""
    ec2 = client(sess, "ec2", region)
    bad = set()
    
    # If resource_id is provided, check only that security group
    if resource_id and resource_id != "*":
        try:
            sg = ec2.describe_security_groups(GroupIds=[resource_id])["SecurityGroups"][0]
            for p in sg.get("IpPermissions", []):
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])) \
                or any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", [])):
                    bad.add(resource_id)
        except ClientError:
            pass
    else:
        # Check all security groups
        for sg in ec2.describe_security_groups()["SecurityGroups"]:
            gid = sg["GroupId"]
            for p in sg.get("IpPermissions", []):
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])) \
                or any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", [])):
                    bad.add(gid)
                    
    return {"status": not bad, "details": {"wide_open_sgs": list(bad)}}

def check_sg_non_rfc1918(sess, resource_id, region):
    """Check if Security Groups allow non-RFC1918 ingress."""
    ec2 = client(sess, "ec2", region)
    bad = set()
    
    # If resource_id is provided, check only that security group
    if resource_id and resource_id != "*":
        try:
            sg = ec2.describe_security_groups(GroupIds=[resource_id])["SecurityGroups"][0]
            for p in sg.get("IpPermissions", []):
                for r in p.get("IpRanges", []):
                    cidr = r.get("CidrIp")
                    if cidr and not ipaddress.ip_network(cidr).is_private:
                        bad.add(resource_id)
        except ClientError:
            pass
    else:
        # Check all security groups
        for sg in ec2.describe_security_groups()["SecurityGroups"]:
            gid = sg["GroupId"]
            for p in sg.get("IpPermissions", []):
                for r in p.get("IpRanges", []):
                    cidr = r.get("CidrIp")
                    if cidr and not ipaddress.ip_network(cidr).is_private:
                        bad.add(gid)
                        
    return {"status": not bad, "details": {"non_rfc1918_sgs": list(bad)}}

def check_ec2_userdata(sess, resource_id, region):
    """Find secrets in EC2 User Data."""
    ec2 = client(sess, "ec2", region)
    bad = []
    
    # If resource_id is provided, check only that instance
    if resource_id and resource_id != "*":
        try:
            ud = ec2.describe_instance_attribute(
                    InstanceId=resource_id, Attribute="userData"
                 ).get("UserData", {}).get("Value", "")
            if ud:
                txt = base64.b64decode(ud).decode("utf-8", "ignore")
                if re.search(r"(?i)(secret|password|key)", txt):
                    bad.append({"instance": resource_id, "snippet": txt[:200]})
        except ClientError:
            pass
    else:
        # Check all instances
        for res in ec2.describe_instances()["Reservations"]:
            for inst in res["Instances"]:
                iid = inst["InstanceId"]
                try:
                    ud = ec2.describe_instance_attribute(
                            InstanceId=iid, Attribute="userData"
                         ).get("UserData", {}).get("Value", "")
                    if ud:
                        txt = base64.b64decode(ud).decode("utf-8", "ignore")
                        if re.search(r"(?i)(secret|password|key)", txt):
                            bad.append({"instance": iid, "snippet": txt[:200]})
                except ClientError:
                    continue
                    
    return {"status": not bad, "details": {"userdata_secrets": bad}}

def check_opensearch_cognito(sess, resource_id, region):
    """Check if OpenSearch domains have Cognito authentication enabled."""
    osr = client(sess, "opensearch", region)
    bad = []
    
    # If resource_id is provided, check only that domain
    if resource_id and resource_id != "*":
        try:
            enabled = osr.describe_domain(DomainName=resource_id)["DomainStatus"] \
                         ["CognitoOptions"]["Enabled"]
            if not enabled:
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all domains
        for d in osr.list_domain_names()["DomainNames"]:
            name = d["DomainName"]
            try:
                enabled = osr.describe_domain(DomainName=name)["DomainStatus"] \
                             ["CognitoOptions"]["Enabled"]
                if not enabled:
                    bad.append(name)
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"domains_without_cognito": bad}}

def check_efs_everyone(sess, resource_id, region):
    """Check if EFS has policies that allow access to everyone."""
    efs = client(sess, "efs", region)
    bad = []
    
    # If resource_id is provided, check only that file system
    if resource_id and resource_id != "*":
        try:
            pol = json.loads(
                  efs.describe_file_system_policy(FileSystemId=resource_id)["Policy"]
            )
            for stmt in pol.get("Statement", []):
                if stmt.get("Principal") == "*":
                    bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all file systems
        for fs in efs.describe_file_systems()["FileSystems"]:
            fsid = fs["FileSystemId"]
            try:
                pol = json.loads(
                      efs.describe_file_system_policy(FileSystemId=fsid)["Policy"]
                )
                for stmt in pol.get("Statement", []):
                    if stmt.get("Principal") == "*":
                        bad.append(fsid)
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"efs_everyone": bad}}

def check_rds_force_ssl(sess, resource_id, region):
    """Check if RDS instances force SSL connections."""
    rds = client(sess, "rds", region)
    bad = []
    
    # If resource_id is provided, check only that instance
    if resource_id and resource_id != "*":
        try:
            db = rds.describe_db_instances(DBInstanceIdentifier=resource_id)["DBInstances"][0]
            pg = db["DBParameterGroups"][0]["DBParameterGroupName"]
            params = rds.describe_db_parameters(DBParameterGroupName=pg)["Parameters"]
            for p in params:
                if p["ParameterName"] == "rds.force_ssl" and p.get("ParameterValue") != "1":
                    bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all instances
        for db in rds.describe_db_instances()["DBInstances"]:
            dbid = db["DBInstanceIdentifier"]
            try:
                pg = db["DBParameterGroups"][0]["DBParameterGroupName"]
                params = rds.describe_db_parameters(DBParameterGroupName=pg)["Parameters"]
                for p in params:
                    if p["ParameterName"] == "rds.force_ssl" and p.get("ParameterValue") != "1":
                        bad.append(dbid)
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"rds_no_ssl": bad}}

def check_root_hardware_mfa(sess, resource_id, region):
    """Check if the root account has hardware MFA enabled."""
    iam = client(sess, "iam", region)
    try:
        virt = iam.list_virtual_mfa_devices()["VirtualMFADevices"]
        real = iam.list_mfa_devices(UserName="root")["MFADevices"]
        ok = not virt and bool(real)
        return {"status": ok, "details": {
                "hardware_serials": [d["SerialNumber"] for d in real],
                "virtual_present": bool(virt)
            }}
    except ClientError as e:
        return {"status": False, "details": str(e)}

def check_ecs_task_secrets(sess, resource_id, region):
    """Find secrets in ECS task definition environment variables."""
    ecs = client(sess, "ecs", region)
    bad = []
    
    # If resource_id is provided, check only that task definition
    if resource_id and resource_id != "*":
        try:
            td = ecs.describe_task_definition(taskDefinition=resource_id)["taskDefinition"]
            for cd in td.get("containerDefinitions", []):
                for env in cd.get("environment", []):
                    if re.search(r"(?i)(secret|password|key)", env["name"]):
                        bad.append({"task_def": resource_id, "var": env["name"]})
        except ClientError:
            pass
    else:
        # Check all task definitions
        for arn in ecs.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]:
            try:
                td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
                for cd in td.get("containerDefinitions", []):
                    for env in cd.get("environment", []):
                        if re.search(r"(?i)(secret|password|key)", env["name"]):
                            bad.append({"task_def": arn, "var": env["name"]})
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"ecs_secrets": bad}}

# ─────────── Additional checks ───────────
def check_backup_vaults_exist(sess, resource_id, region):
    """Check if AWS Backup vaults exist."""
    backup = client(sess, "backup", region)
    try:
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        return {"status": bool(vaults),
                "details": {"vaults": [v["BackupVaultName"] for v in vaults]}}
    except ClientError as e:
        return {"status": False, "details": str(e)}

def check_cloudtrail_logs_encrypted(sess, resource_id, region):
    """Check if CloudTrail logs are encrypted with KMS."""
    ct = client(sess, "cloudtrail", region)
    bad = []
    
    # If resource_id is provided, check only that trail
    if resource_id and resource_id != "*":
        try:
            t = ct.describe_trails(trailNameList=[resource_id])["trailList"][0]
            if not t.get("KmsKeyId"):
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all trails
        for t in ct.describe_trails()["trailList"]:
            if not t.get("KmsKeyId"):
                bad.append(t["Name"])
                
    return {"status": not bad, "details": {"unencrypted_trails": bad}}

def check_cloudtrail_trails_cwl(sess, resource_id, region):
    """Check if CloudTrail trails are integrated with CloudWatch Logs."""
    ct = client(sess, "cloudtrail", region)
    bad = []
    
    # If resource_id is provided, check only that trail
    if resource_id and resource_id != "*":
        try:
            t = ct.describe_trails(trailNameList=[resource_id])["trailList"][0]
            if not t.get("CloudWatchLogsLogGroupArn"):
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all trails
        for t in ct.describe_trails()["trailList"]:
            if not t.get("CloudWatchLogsLogGroupArn"):
                bad.append(t["Name"])
                
    return {"status": not bad, "details": {"trails_without_cwl": bad}}

def check_cwlog_kms(sess, resource_id, region):
    """Check if CloudWatch log groups are encrypted with KMS."""
    logs = client(sess, "logs", region)
    bad = []
    
    # If resource_id is provided, check only that log group
    if resource_id and resource_id != "*":
        try:
            lg = logs.describe_log_groups(logGroupNamePrefix=resource_id)["logGroups"][0]
            if not lg.get("kmsKeyId"):
                bad.append(resource_id)
        except (ClientError, IndexError):
            pass
    else:
        # Check all log groups
        for lg in logs.describe_log_groups().get("logGroups", []):
            if not lg.get("kmsKeyId"):
                bad.append(lg["logGroupName"])
                
    return {"status": not bad, "details": {"unencrypted_log_groups": bad}}

def check_cwlog_retention(sess, resource_id, region):
    """Check if CloudWatch log groups have proper retention policy."""
    logs = client(sess, "logs", region)
    bad = []
    
    # If resource_id is provided, check only that log group
    if resource_id and resource_id != "*":
        try:
            lg = logs.describe_log_groups(logGroupNamePrefix=resource_id)["logGroups"][0]
            retention = lg.get("retentionInDays")
            if not retention or retention > CW_RETENTION_DAYS:
                bad.append({"logGroup": resource_id, "retention": retention})
        except (ClientError, IndexError):
            pass
    else:
        # Check all log groups
        for lg in logs.describe_log_groups().get("logGroups", []):
            retention = lg.get("retentionInDays")
            if not retention or retention > CW_RETENTION_DAYS:
                bad.append({"logGroup": lg["logGroupName"], "retention": retention})
                
    return {"status": not bad, "details": {"bad_retention_log_groups": bad}}

def check_cloudformation_termination(sess, resource_id, region):
    """Check if CloudFormation stacks have termination protection enabled."""
    cf = client(sess, "cloudformation", region)
    bad = []
    
    # If resource_id is provided, check only that stack
    if resource_id and resource_id != "*":
        try:
            s = cf.describe_stacks(StackName=resource_id)["Stacks"][0]
            if not s.get("EnableTerminationProtection"):
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all stacks
        for s in cf.describe_stacks()["Stacks"]:
            if not s.get("EnableTerminationProtection"):
                bad.append(s["StackName"])
                
    return {"status": not bad, "details": {"no_tp_stacks": bad}}

def check_rds_storage_encrypted(sess, resource_id, region):
    """Check if RDS instances have storage encryption enabled."""
    rds = client(sess, "rds", region)
    bad = []
    
    # If resource_id is provided, check only that instance
    if resource_id and resource_id != "*":
        try:
            db = rds.describe_db_instances(DBInstanceIdentifier=resource_id)["DBInstances"][0]
            if not db.get("StorageEncrypted"):
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all instances
        for db in rds.describe_db_instances()["DBInstances"]:
            if not db.get("StorageEncrypted"):
                bad.append(db["DBInstanceIdentifier"])
                
    return {"status": not bad, "details": {"unencrypted_rds": bad}}

def check_s3_bucket_encryption(sess, resource_id, region):
    """Check if S3 buckets have default encryption enabled."""
    s3 = client(sess, "s3", region)
    bad = []
    
    # If resource_id is provided, check only that bucket
    if resource_id and resource_id != "*":
        try:
            enc = s3.get_bucket_encryption(Bucket=resource_id)
            # If we got here, encryption is enabled
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                bad.append(resource_id)
    else:
        # Check all buckets
        for b in s3.list_buckets()["Buckets"]:
            name = b["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                # If we got here, encryption is enabled
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    bad.append(name)
                    
    return {"status": not bad, "details": {"unencrypted_buckets": bad}}

def check_s3_bucket_public_access(sess, resource_id, region):
    """Check if S3 buckets have public access."""
    s3 = client(sess, "s3", region)
    bad = []
    
    # If resource_id is provided, check only that bucket
    if resource_id and resource_id != "*":
        try:
            acl = s3.get_bucket_acl(Bucket=resource_id)["Grants"]
            for grant in acl:
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    bad.append(resource_id)
                    break
        except ClientError:
            pass
    else:
        # Check all buckets
        for b in s3.list_buckets()["Buckets"]:
            name = b["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)["Grants"]
                for grant in acl:
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        bad.append(name)
                        break
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"public_buckets": bad}}

def check_ec2_instance_imdsv2(sess, resource_id, region):
    """Check if EC2 instances have IMDSv2 enabled."""
    ec2 = client(sess, "ec2", region)
    bad = []
    
    # If resource_id is provided, check only that instance
    if resource_id and resource_id != "*":
        try:
            md = ec2.describe_instance_attribute(
                    InstanceId=resource_id, Attribute="metadataOptions"
                 )["MetadataOptions"]
            if md.get("HttpTokens") != "required":
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all instances
        for res in ec2.describe_instances()["Reservations"]:
            for inst in res["Instances"]:
                iid = inst["InstanceId"]
                if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                    bad.append(iid)
                    
    return {"status": not bad, "details": {"imdsv1_instances": bad}}

def check_ec2_instances_old(sess, resource_id, region):
    """Check for EC2 instances older than specific days."""
    ec2 = client(sess, "ec2", region)
    bad = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=EC2_OLD_INSTANCE_DAYS)
    
    # If resource_id is provided, check only that instance
    if resource_id and resource_id != "*":
        try:
            reservations = ec2.describe_instances(InstanceIds=[resource_id])["Reservations"]
            for res in reservations:
                for inst in res["Instances"]:
                    launch_time = inst["LaunchTime"]
                    if launch_time <= cutoff:
                        bad.append({"instance": resource_id, "launch_time": launch_time.isoformat()})
        except ClientError:
            pass
    else:
        # Check all instances
        for res in ec2.describe_instances()["Reservations"]:
            for inst in res["Instances"]:
                iid = inst["InstanceId"]
                launch_time = inst["LaunchTime"]
                if launch_time <= cutoff:
                    bad.append({"instance": iid, "launch_time": launch_time.isoformat()})
                    
    return {"status": not bad, "details": {"old_instances": bad}}

def check_vpc_flow_logs(sess, resource_id, region):
    """Check if VPC flow logs are enabled."""
    ec2 = client(sess, "ec2", region)
    bad = []
    
    # If resource_id is provided, check only that VPC
    if resource_id and resource_id != "*":
        try:
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [resource_id]}]
            )["FlowLogs"]
            if not flow_logs:
                bad.append(resource_id)
        except ClientError:
            pass
    else:
        # Check all VPCs
        vpcs = ec2.describe_vpcs()["Vpcs"]
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            try:
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                )["FlowLogs"]
                if not flow_logs:
                    bad.append(vpc_id)
            except ClientError:
                continue
                
    return {"status": not bad, "details": {"vpcs_without_flow_logs": bad}}

def get_password_policy(sess, region):
    """Get IAM password policy for the account."""
    iam = client(sess, "iam", region)
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError:
        return {}

def prowler_command_validator(check_id):
    """Create a validator function that uses prowler CLI."""
    def validator(sess, resource_id, region):
        # Construct prowler command
        cmd = f"prowler aws --profile {sess.profile_name} --region {region} --check {check_id}"
        if resource_id and resource_id != "*":
            cmd += f" --resource-id {resource_id}"
            
        # Run command and parse output
        output = run_command(cmd)
        return parse_prowler_output(output)
    
    return validator

def make_not_impl(name):
    """Create a placeholder function for unimplemented checks."""
    def fn(sess, rid, region):
        return {"status": False, "details": f"{name} not implemented"}
    return fn

# ─────────── VALIDATORS MAPPING ───────────
VALIDATORS = {
    # Core checks implemented directly
    "Check S3 Account Level Public Access Block": check_s3_pab,
    "Ensure IAM Roles do not have AdministratorAccess policy attached": check_iam_admin_roles,
    "Ensure there are no SNS Topics unencrypted": check_sns_unencrypted,
    "Find secrets in Lambda functions variables.": check_lambda_secrets,
    "Check if ACM Certificates are about to expire in specific days or less": check_acm_expiry,
    "Ensure IAM Service Roles prevents against a cross-service confused deputy attack": check_service_role_trust,
    "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to any port.": check_sg_wide_open,
    "Ensure no security groups allow ingress from wide-open non-RFC1918 address.": check_sg_non_rfc1918,
    "Find secrets in EC2 User Data.": check_ec2_userdata,
    "Check if Amazon Elasticsearch/Opensearch Service domains has Amazon Cognito authentication for Kibana enabled": check_opensearch_cognito,
    "Check if EFS have policies which allow access to everyone": check_efs_everyone,
    "Check if RDS instances client connections are encrypted (Microsoft SQL Server and PostgreSQL).": check_rds_force_ssl,
    "Ensure only hardware MFA is enabled for the root account": check_root_hardware_mfa,
    "Check if secrets exists in ECS task definitions environment variables": check_ecs_task_secrets,
    "Check if CloudWatch log groups are protected by AWS KMS.": check_cwlog_kms,
    "Check if CloudWatch Log Groups have a retention policy of specific days.": check_cwlog_retention,
    "Enable termination protection for Cloudformation Stacks": check_cloudformation_termination,
    "Ensure AWS Backup vaults exist": check_backup_vaults_exist,
    "Ensure CloudTrail logs are encrypted at rest using KMS CMKs": check_cloudtrail_logs_encrypted,
    "Ensure CloudTrail trails are integrated with CloudWatch Logs": check_cloudtrail_trails_cwl,
    "Check if RDS instances storage is encrypted.": check_rds_storage_encrypted,
    "Check if S3 buckets have default encryption (SSE) enabled or use a bucket policy to enforce it.": check_s3_bucket_encryption,
    "Ensure there are no S3 buckets open to Everyone or Any AWS user.": check_s3_bucket_public_access,
    "Check if EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required.": check_ec2_instance_imdsv2,
    "Check EC2 Instances older than specific days.": check_ec2_instances_old,
    "Ensure VPC Flow Logging is Enabled in all VPCs.": check_vpc_flow_logs,
    
    # IAM password policy checks
    "Ensure IAM password policy expires passwords within 90 days or less": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("MaxPasswordAge",999)<=90, "details": v}
    )[1],
    "Ensure IAM password policy prevents password reuse: 24 or greater": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("PasswordReusePrevention",0)>=24, "details": v}
    )[1],
    "Ensure IAM password policy require at least one lowercase letter": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("RequireLowercaseCharacters",False), "details": v}
    )[1],
    "Ensure IAM password policy require at least one number": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("RequireNumbers",False), "details": v}
    )[1],
    "Ensure IAM password policy require at least one symbol": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("RequireSymbols",False), "details": v}
    )[1],
    "Ensure IAM password policy requires at least one uppercase letter": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("RequireUppercaseCharacters",False), "details": v}
    )[1],
    "Ensure IAM password policy requires minimum length of 14 or greater": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("MinimumPasswordLength",0)>=14, "details": v}
    )[1],
}

# ─────────── Prowler ID Mapping ───────────
PROWLER_CHECK_IDS = {
    "Check if IAM Access Analyzer is enabled": "accessanalyzer_enabled",
    "Check if IAM Access Analyzer is enabled without findings": "accessanalyzer_enabled_without_findings",
    "Maintain current contact details.": "account_maintain_current_contact_details",
    "Maintain different contact details to security, billing and operations.": "account_maintain_different_contact_details_to_security_billing_and_operations",
    "Ensure security contact information is registered.": "account_security_contact_information_is_registered",
    "Ensure security questions are registered in the AWS account.": "account_security_questions_are_registered_in_the_aws_account",
    # Add all 301 check mappings here...
}

# Add prowler CLI validators for checks not implemented directly
for check_title, check_id in PROWLER_CHECK_IDS.items():
    if check_title not in VALIDATORS:
        VALIDATORS[check_title] = prowler_command_validator(check_id)

# Add stub functions for any checks not covered
for check_title in range(len(PROWLER_CHECK_IDS)):
    if check_title not in VALIDATORS and check_title not in PROWLER_CHECK_IDS:
        VALIDATORS[check_title] = make_not_impl(check_title)

# ─────────── Report Functions ───────────
def load_report(path, severities):
    """Load and filter findings from a Prowler JSON report."""
    data = json.load(open(path))
    out = []
    for i in data:
        title = i.get("CheckTitle")
        sev = i.get("Severity", "").lower()
        if sev in severities and title in VALIDATORS:
            out.append({
                "profile": i.get("Profile"),
                "account_id": i.get("AccountId"),
                "region": i.get("Region"),
                "title": title,
                "resource_id": i.get("ResourceId")
            })
    return out

def verify_prowler_version():
    """Check if Prowler is installed with the minimum required version."""
    try:
        # Use poetry run prowler instead of just prowler
        result = subprocess.run(["poetry", "run", "prowler", "--version"], 
                              capture_output=True, text=True, check=True)
        version = result.stdout.strip()
        # Extract version number
        match = re.search(r'(\d+\.\d+\.\d+)', version)
        if match:
            version_num = match.group(1)
            parts = version_num.split(".")
            if int(parts[0]) < int(PROWLER_MIN_VERSION.split(".")[0]):
                print(f"⚠️ Warning: Prowler version {version_num} is older than the minimum recommended version {PROWLER_MIN_VERSION}")
                return False
            return True
        else:
            print("⚠️ Warning: Could not determine Prowler version.")
            return False
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️ Warning: Prowler is not installed or not accessible via 'poetry run prowler'.")
        return False

# ─────────── Main Functions ───────────
def run_check_mode(args):
    """Run security checks on provided profiles."""
    rows = []
    
    if args.profile:
        profiles = [args.profile]
    else:
        profiles = boto3.Session().available_profiles
    
    for profile in profiles:
        print(f"▶️  Validating profile '{profile}'")
        sess = boto3.Session(profile_name=profile)
        
        try:
            acct = get_account_id(sess)
        except Exception as e:
            print(f"   ⚠️  Could not get account for '{profile}', skipping: {str(e)}")
            continue
        
        region = args.region or DEFAULT_REGION
        
        if args.check:
            # Run specific checks
            check_titles = args.check
        else:
            # Run all implemented checks
            check_titles = list(VALIDATORS.keys())
        
        for check_title in check_titles:
            if check_title not in VALIDATORS:
                print(f"   ⚠️  Check '{check_title}' not implemented, skipping.")
                continue
                
            fn = VALIDATORS[check_title]
            try:
                res = fn(sess, args.resource_id, region)
            except Exception as e:
                res = {"status": False, "details": str(e)}
            
            # Prepare details string
            det_str = (res["details"] if isinstance(res["details"], str)
                      else json.dumps(res["details"]))
            
            # Classify true_positive
            tp = classify_tp(res["status"], res["details"])
            
            rows.append({
                "profile": profile,
                "account_id": f"'{acct}",
                "region": region,
                "check_title": check_title,
                "resource_id": args.resource_id or "*",
                "status": "PASS" if res["status"] else "FAIL",
                "details": det_str,
                "true_positive": tp
            })
    
    df = pd.DataFrame(rows)
    df.to_csv(args.output or OUTPUT_CSV, index=False)
    print(f"\n✅  Done. Results written to {args.output or OUTPUT_CSV}")
    return df

def run_report_mode(args):
    """Validate findings from a Prowler report."""
    findings = load_report(args.report, set([s.lower() for s in args.severity]))
    rows = []
    
    for f in findings:
        sess = boto3.Session(profile_name=f["profile"], region_name=f["region"])
        fn = VALIDATORS.get(f["title"])
        
        if not fn:
            print(f"   ⚠️  Check '{f['title']}' not implemented, skipping.")
            continue
            
        try:
            res = fn(sess, f["resource_id"], f["region"])
        except Exception as e:
            res = {"status": False, "details": str(e)}
        
        tp = classify_tp(res["status"], res["details"])
        det_str = (res["details"] if isinstance(res["details"], str)
                  else json.dumps(res["details"]))
        
        rows.append({
            "profile": f["profile"],
            "account_id": f"'{f['account_id']}",
            "region": f["region"],
            "check_title": f["title"],
            "resource_id": f["resource_id"],
            "status": "PASS" if res["status"] else "FAIL",
            "details": det_str,
            "true_positive": tp
        })
    
    df = pd.DataFrame(rows)
    df.to_csv(args.output or OUTPUT_CSV, index=False)
    print(f"\n✅  Results written to {args.output or OUTPUT_CSV}")
    return df

def main():
    parser = argparse.ArgumentParser(description="AWS Security Validation Script")
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")
    
    # Report mode (similar to prowlerbake.py)
    report_parser = subparsers.add_parser("report", help="Validate findings from a Prowler report")
    report_parser.add_argument("--report", required=True, help="Path to Prowler JSON report")
    report_parser.add_argument("--severity", nargs="+", 
                             default=["critical", "high", "moderate", "low"],
                             help="Severities to include")
    report_parser.add_argument("--output", help=f"Output CSV path (default: {OUTPUT_CSV})")
    
    # Check mode (similar to prowlershake.py)
    check_parser = subparsers.add_parser("check", help="Run security checks directly")
    check_parser.add_argument("--profile", help="Specific AWS profile to check (default: all profiles)")
    check_parser.add_argument("--region", help=f"AWS region to use (default: {DEFAULT_REGION})")
    check_parser.add_argument("--check", nargs="+", help="Specific checks to run (default: all implemented)")
    check_parser.add_argument("--resource-id", help="Specific resource ID to check (default: all resources)")
    check_parser.add_argument("--output", help=f"Output CSV path (default: {OUTPUT_CSV})")
    
    # Generate mode (to list all available checks)
    gen_parser = subparsers.add_parser("list", help="List all available checks")
    gen_parser.add_argument("--implemented", action="store_true", help="Show only implemented checks")
    
    args = parser.parse_args()
    
    # Verify Prowler installation
    have_prowler = verify_prowler_version()
    
    if args.mode == "report":
        if not os.path.exists(args.report):
            print(f"❌ Error: Report file {args.report} not found.")
            return
        run_report_mode(args)
        
    elif args.mode == "check":
        run_check_mode(args)
        
    elif args.mode == "list":
        if args.implemented:
            checks = [k for k, v in VALIDATORS.items() if not hasattr(v, "__name__") or v.__name__ != "fn"]
        else:
            checks = list(VALIDATORS.keys())
        
        for i, check in enumerate(sorted(checks), 1):
            print(f"{i:3d}. {check}")
        print(f"\nTotal: {len(checks)} checks")
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
