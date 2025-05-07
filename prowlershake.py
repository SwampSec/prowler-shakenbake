#!/usr/bin/env python3
import boto3
import pandas as pd
import base64
import re
import json
import ipaddress
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoRegionError

# ──────────── Configuration ────────────
OUTPUT_CSV     = "aws_validation_results.csv"
ACM_EXPIRY_DAYS = 30
DEFAULT_REGION = "us-east-1"

# ──────────── Helpers ────────────
def client(session, service):
    """Create client with a default region fallback."""
    try:
        return session.client(service)
    except NoRegionError:
        return session.client(service, region_name=DEFAULT_REGION)

def get_account_id(session):
    return client(session, 'sts').get_caller_identity()['Account']

# ──────────── Validators ────────────

def check_s3_pab(sess):
    c = client(sess, 's3control')
    try:
        acct = get_account_id(sess)
        resp = c.get_public_access_block(AccountId=acct)
        cfg = resp['PublicAccessBlockConfiguration']
        ok = all(cfg.get(f, False) for f in [
            'BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets'
        ])
        return {"status": ok, "details": cfg}
    except ClientError as e:
        return {"status": False, "details": str(e)}

def check_iam_admin_roles(sess):
    iam = client(sess, 'iam')
    bad = []
    for r in iam.list_roles()['Roles']:
        at = iam.list_attached_role_policies(RoleName=r['RoleName'])['AttachedPolicies']
        if any(p['PolicyName']=='AdministratorAccess' for p in at):
            bad.append(r['RoleName'])
    return {"status": not bad, "details": {"admin_roles": bad}}

def check_sns_unencrypted(sess):
    sns = client(sess, 'sns')
    bad = []
    for t in sns.list_topics()['Topics']:
        arn = t['TopicArn']
        kms = sns.get_topic_attributes(TopicArn=arn)['Attributes'].get('KmsMasterKeyId')
        if not kms or kms == "None":
            bad.append(arn)
    return {"status": not bad, "details": {"unencrypted_topics": bad}}

def check_lambda_secrets(sess):
    lam = client(sess, 'lambda')
    bad = []
    for fn in lam.list_functions()['Functions']:
        name = fn['FunctionName']
        env = lam.get_function_configuration(FunctionName=name)\
                 .get('Environment', {}).get('Variables', {})
        for k,v in env.items():
            if re.search(r'(?i)(secret|password|key)', k):
                bad.append({name:{k:v}})
    return {"status": not bad, "details": {"lambda_secrets": bad}}

def check_acm_expiry(sess):
    acm = client(sess, 'acm')
    bad = []
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=ACM_EXPIRY_DAYS)
    for cert in acm.list_certificates()['CertificateSummaryList']:
        arn = cert['CertificateArn']
        not_after = acm.describe_certificate(CertificateArn=arn)\
                       ['Certificate']['NotAfter']
        if not_after <= cutoff:
            bad.append({"arn": arn, "expires": not_after.isoformat()})
    return {"status": not bad, "details": {"expiring_certs": bad}}

def check_service_role_trust(sess):
    iam = client(sess, 'iam')
    bad = []
    for r in iam.list_roles()['Roles']:
        name = r['RoleName']
        if 'service-role' in name or name.startswith('AWSServiceRoleFor'):
            doc = iam.get_role(RoleName=name)['Role']['AssumeRolePolicyDocument']
            for s in doc.get('Statement', []):
                if s.get('Effect')=='Allow' and not s.get('Condition'):
                    bad.append(name)
                    break
    return {"status": not bad, "details": {"roles_missing_conditions": bad}}

def check_sg_wide_open(sess):
    ec2 = client(sess, 'ec2')
    bad = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        gid = sg['GroupId']
        for p in sg.get('IpPermissions', []):
            if any(r.get('CidrIp')=='0.0.0.0/0' for r in p.get('IpRanges', [])) \
            or any(r.get('CidrIpv6')=='::/0' for r in p.get('Ipv6Ranges', [])):
                bad.append(gid)
    return {"status": not bad, "details": {"wide_open_sgs": list(set(bad))}}

def check_sg_non_rfc1918(sess):
    ec2 = client(sess, 'ec2')
    bad = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        gid = sg['GroupId']
        for p in sg.get('IpPermissions', []):
            for r in p.get('IpRanges', []):
                cidr = r.get('CidrIp')
                if cidr and not ipaddress.ip_network(cidr).is_private:
                    bad.append(gid)
    return {"status": not bad, "details": {"non_rfc1918_sgs": list(set(bad))}}

def check_ec2_userdata(sess):
    ec2 = client(sess, 'ec2')
    bad = []
    for res in ec2.describe_instances()['Reservations']:
        for inst in res['Instances']:
            iid = inst['InstanceId']
            try:
                ud = ec2.describe_instance_attribute(InstanceId=iid,Attribute='userData')
                val = ud.get('UserData',{}).get('Value','')
                txt = base64.b64decode(val).decode('utf-8','ignore')
                if re.search(r'(?i)(secret|password|key)', txt):
                    bad.append({"instance": iid, "snippet": txt[:200]})
            except ClientError:
                continue
    return {"status": not bad, "details": {"userdata_secrets": bad}}

def check_opensearch_cognito(sess):
    osr = client(sess, 'opensearch')
    bad = []
    for d in osr.list_domain_names()['DomainNames']:
        name = d['DomainName']
        enabled = osr.describe_domain(DomainName=name)['DomainStatus']\
                      ['CognitoOptions']['Enabled']
        if not enabled:
            bad.append(name)
    return {"status": not bad, "details": {"domains_without_cognito": bad}}

def check_efs_everyone(sess):
    efs = client(sess, 'efs')
    bad = []
    for fs in efs.describe_file_systems()['FileSystems']:
        fsid = fs['FileSystemId']
        try:
            pol = json.loads(efs.describe_file_system_policy(FileSystemId=fsid)['Policy'])
            for stmt in pol.get('Statement', []):
                if stmt.get('Principal') == "*":
                    bad.append(fsid)
        except ClientError:
            continue
    return {"status": not bad, "details": {"efs_everyone": bad}}

def check_rds_force_ssl(sess):
    rds = client(sess, 'rds')
    bad = []
    for db in rds.describe_db_instances()['DBInstances']:
        dbid = db['DBInstanceIdentifier']
        pg   = db['DBParameterGroups'][0]['DBParameterGroupName']
        params = rds.describe_db_parameters(DBParameterGroupName=pg)['Parameters']
        for p in params:
            if p['ParameterName']=='rds.force_ssl' and p.get('ParameterValue')!='1':
                bad.append(dbid)
    return {"status": not bad, "details": {"rds_no_ssl": bad}}

def check_root_hardware_mfa(sess):
    iam = client(sess, 'iam')
    virt = iam.list_virtual_mfa_devices()['VirtualMFADevices']
    real = iam.list_mfa_devices(UserName='root')['MFADevices']
    status = not virt and bool(real)
    return {"status": status, "details": {"hardware_serials": [d['SerialNumber'] for d in real], "virtual_present": bool(virt)}}

def check_ecs_task_secrets(sess):
    ecs = client(sess, 'ecs')
    bad = []
    for arn in ecs.list_task_definitions(status='ACTIVE')['taskDefinitionArns']:
        td = ecs.describe_task_definition(taskDefinition=arn)['taskDefinition']
        for cd in td.get('containerDefinitions', []):
            for env in cd.get('environment', []):
                if re.search(r'(?i)(secret|password|key)', env['name']):
                    bad.append({"task_def": arn, "var": env['name']})
    return {"status": not bad, "details": {"ecs_secrets": bad}}

# ──────────── Map your 14 checks ────────────
VALIDATORS = {
    "S3 Public Access Block":          check_s3_pab,
    "IAM AdminAccess Attached":        check_iam_admin_roles,
    "SNS Topics Unencrypted":          check_sns_unencrypted,
    "Lambda Env Secrets":              check_lambda_secrets,
    "ACM Certs Expiring Soon":         check_acm_expiry,
    "Service Role Deputies":           check_service_role_trust,
    "SG Wide Open (0/0)":              check_sg_wide_open,
    "SG Non-RFC1918 Ingress":          check_sg_non_rfc1918,
    "EC2 UserData Secrets":            check_ec2_userdata,
    "OpenSearch Cognito for Kibana":   check_opensearch_cognito,
    "EFS Everyone-Allowed":            check_efs_everyone,
    "RDS Enforce SSL":                 check_rds_force_ssl,
    "Root Hardware MFA Only":          check_root_hardware_mfa,
    "ECS TaskDef Env Secrets":         check_ecs_task_secrets,
}

if len(VALIDATORS) != 14:
    raise RuntimeError(f"Expected 14 validators, found {len(VALIDATORS)}")

# ──────────── Main ────────────
def main():
    rows     = []
    profiles = boto3.Session().available_profiles

    for profile in profiles:
        print(f"▶️  Validating profile '{profile}'")
        sess = boto3.Session(profile_name=profile)
        try:
            acct = get_account_id(sess)
        except Exception:
            print(f"   ⚠️  Could not get account for '{profile}', skipping.")
            continue

        for cat, fn in VALIDATORS.items():
            try:
                res = fn(sess)
            except Exception as e:
                res = {"status": False, "details": str(e)}

            # prepare details string
            det = res.get("details", "")
            det_str = det if isinstance(det, str) else json.dumps(det)

            # classify true_positive
            if res["status"]:
                tp = ""
            else:
                if "AccessDeniedException" in det_str:
                    tp = "FALSE"
                else:
                    try:
                        d = json.loads(det_str)
                        tp = "TRUE" if any(isinstance(v, list) and v for v in d.values()) else "FALSE"
                    except:
                        tp = "FALSE"

            rows.append({
                "profile":       profile,
                "account_id":    f"'{acct}",
                "category":      cat,
                "status":        "PASS" if res["status"] else "FAIL",
                "details":       det_str,
                "true_positive": tp
            })

    pd.DataFrame(rows).to_csv(OUTPUT_CSV, index=False)
    print(f"\n✅  Done. Results written to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
