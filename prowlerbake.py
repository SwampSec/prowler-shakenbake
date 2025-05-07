#!/usr/bin/env python3
import argparse
import boto3
import pandas as pd
import json
import re
import base64
import ipaddress
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoRegionError

# ─────────── Configuration ───────────
OUTPUT_CSV        = "aws_validation_results.csv"
ACM_EXPIRY_DAYS   = 30
CW_RETENTION_DAYS = 90
DEFAULT_REGION    = "us-east-1"

# ─────────── Helpers ───────────
def client(session, service, region=None):
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    try:
        return session.client(service, **kwargs)
    except NoRegionError:
        return session.client(service, region_name=DEFAULT_REGION)

def get_account_id(session):
    return client(session, "sts").get_caller_identity()["Account"]

def classify_tp(status, details):
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

# ─────────── Validators ───────────
# Signature: fn(session, resource_id, region) -> {"status":bool,"details":...}

def check_s3_pab(sess, resource_id, region):
    s3c = client(sess, "s3control", region)
    try:
        acct = get_account_id(sess)
        cfg  = s3c.get_public_access_block(AccountId=acct)["PublicAccessBlockConfiguration"]
        ok   = all(cfg.get(f, False) for f in (
            "BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets"
        ))
        return {"status": ok, "details": cfg}
    except ClientError as e:
        return {"status": False, "details": str(e)}

def check_iam_admin_roles(sess, resource_id, region):
    iam = client(sess, "iam", region)
    bad = []
    for r in iam.list_roles()["Roles"]:
        attached = iam.list_attached_role_policies(RoleName=r["RoleName"])["AttachedPolicies"]
        if any(p["PolicyName"]=="AdministratorAccess" for p in attached):
            bad.append(r["RoleName"])
    return {"status": not bad, "details": {"admin_roles": bad}}

def check_sns_unencrypted(sess, resource_id, region):
    sns = client(sess, "sns", region)
    bad = []
    for t in sns.list_topics()["Topics"]:
        arn = t["TopicArn"]
        kms = sns.get_topic_attributes(TopicArn=arn)["Attributes"].get("KmsMasterKeyId")
        if not kms or kms=="None":
            bad.append(arn)
    return {"status": not bad, "details": {"unencrypted_topics": bad}}

def check_lambda_secrets(sess, resource_id, region):
    lam = client(sess, "lambda", region)
    bad = []
    for fn in lam.list_functions()["Functions"]:
        name = fn["FunctionName"]
        env  = lam.get_function_configuration(FunctionName=name)\
                   .get("Environment",{}).get("Variables",{})
        for k,v in env.items():
            if re.search(r"(?i)(secret|password|key)", k):
                bad.append({name:{k:v}})
    return {"status": not bad, "details": {"lambda_secrets": bad}}

def check_acm_expiry(sess, resource_id, region):
    acm = client(sess, "acm", region)
    bad = []
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=ACM_EXPIRY_DAYS)
    for cert in acm.list_certificates()["CertificateSummaryList"]:
        arn = cert["CertificateArn"]
        na  = acm.describe_certificate(CertificateArn=arn)["Certificate"]["NotAfter"]
        if na <= cutoff:
            bad.append({"arn": arn, "expires": na.isoformat()})
    return {"status": not bad, "details": {"expiring_certs": bad}}

def check_service_role_trust(sess, resource_id, region):
    iam = client(sess, "iam", region)
    bad = []
    for r in iam.list_roles()["Roles"]:
        name = r["RoleName"]
        if "service-role" in name or name.startswith("AWSServiceRoleFor"):
            doc = iam.get_role(RoleName=name)["Role"]["AssumeRolePolicyDocument"]
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect")=="Allow" and not stmt.get("Condition"):
                    bad.append(name)
                    break
    return {"status": not bad, "details": {"roles_missing_conditions": bad}}

def check_sg_wide_open(sess, resource_id, region):
    ec2 = client(sess, "ec2", region)
    bad = set()
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        gid = sg["GroupId"]
        for p in sg.get("IpPermissions",[]):
            if any(r.get("CidrIp")=="0.0.0.0/0" for r in p.get("IpRanges",[])) \
            or any(r.get("CidrIpv6")=="::/0" for r in p.get("Ipv6Ranges",[])):
                bad.add(gid)
    return {"status": not bad, "details": {"wide_open_sgs": list(bad)}}

def check_sg_non_rfc1918(sess, resource_id, region):
    ec2 = client(sess, "ec2", region)
    bad = set()
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        gid = sg["GroupId"]
        for p in sg.get("IpPermissions",[]):
            for r in p.get("IpRanges",[]):
                cidr = r.get("CidrIp")
                if cidr and not ipaddress.ip_network(cidr).is_private:
                    bad.add(gid)
    return {"status": not bad, "details": {"non_rfc1918_sgs": list(bad)}}

def check_ec2_userdata(sess, resource_id, region):
    ec2 = client(sess, "ec2", region)
    bad = []
    for res in ec2.describe_instances()["Reservations"]:
        for inst in res["Instances"]:
            iid = inst["InstanceId"]
            try:
                ud = ec2.describe_instance_attribute(
                        InstanceId=iid, Attribute="userData"
                     ).get("UserData", {}).get("Value","")
                txt = base64.b64decode(ud).decode("utf-8","ignore")
                if re.search(r"(?i)(secret|password|key)", txt):
                    bad.append({"instance": iid, "snippet": txt[:200]})
            except ClientError:
                pass
    return {"status": not bad, "details": {"userdata_secrets": bad}}

def check_opensearch_cognito(sess, resource_id, region):
    osr = client(sess, "opensearch", region)
    bad=[]
    for d in osr.list_domain_names()["DomainNames"]:
        name    = d["DomainName"]
        enabled = osr.describe_domain(DomainName=name)["DomainStatus"] \
                     ["CognitoOptions"]["Enabled"]
        if not enabled:
            bad.append(name)
    return {"status": not bad, "details": {"domains_without_cognito": bad}}

def check_efs_everyone(sess, resource_id, region):
    efs = client(sess, "efs", region)
    bad=[]
    for fs in efs.describe_file_systems()["FileSystems"]:
        fsid=fs["FileSystemId"]
        try:
            pol = json.loads(
                  efs.describe_file_system_policy(FileSystemId=fsid)["Policy"]
            )
            for stmt in pol.get("Statement",[]):
                if stmt.get("Principal")=="*":
                    bad.append(fsid)
        except ClientError:
            pass
    return {"status": not bad, "details": {"efs_everyone": bad}}

def check_rds_force_ssl(sess, resource_id, region):
    rds = client(sess, "rds", region)
    bad=[]
    for db in rds.describe_db_instances()["DBInstances"]:
        dbid = db["DBInstanceIdentifier"]
        pg   = db["DBParameterGroups"][0]["DBParameterGroupName"]
        params = rds.describe_db_parameters(
                    DBParameterGroupName=pg
                 )["Parameters"]
        for p in params:
            if p["ParameterName"]=="rds.force_ssl" and p.get("ParameterValue")!="1":
                bad.append(dbid)
    return {"status": not bad, "details": {"rds_no_ssl": bad}}

def check_root_hardware_mfa(sess, resource_id, region):
    iam = client(sess, "iam", region)
    virt=iam.list_virtual_mfa_devices()["VirtualMFADevices"]
    real=iam.list_mfa_devices(UserName="root")["MFADevices"]
    ok = not virt and bool(real)
    return {"status": ok, "details":
            {"hardware_serials":[d["SerialNumber"] for d in real],
             "virtual_present": bool(virt)}}

def check_ecs_task_secrets(sess, resource_id, region):
    ecs = client(sess, "ecs", region)
    bad=[]
    for arn in ecs.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]:
        td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
        for cd in td.get("containerDefinitions",[]):
            for env in cd.get("environment",[]):
                if re.search(r"(?i)(secret|password|key)", env["name"]):
                    bad.append({"task_def":arn,"var":env["name"]})
    return {"status": not bad, "details": {"ecs_secrets": bad}}

# ─────────── Additional checks ───────────
def check_backup_vaults_exist(sess, resource_id, region):
    backup = client(sess, "backup", region)
    vaults = backup.list_backup_vaults().get("BackupVaultList",[])
    return {"status": bool(vaults),
            "details": {"vaults":[v["BackupVaultName"] for v in vaults]}}

def check_cloudtrail_logs_encrypted(sess, resource_id, region):
    ct  = client(sess, "cloudtrail", region)
    bad = [t["Name"] for t in ct.describe_trails()["trailList"]
           if not t.get("KmsKeyId")]
    return {"status": not bad, "details": {"unencrypted_trails": bad}}

def check_cloudtrail_trails_cwl(sess, resource_id, region):
    ct  = client(sess, "cloudtrail", region)
    bad = [t["Name"] for t in ct.describe_trails()["trailList"]
           if not t.get("CloudWatchLogsLogGroupArn")]
    return {"status": not bad, "details": {"trails_without_cwl": bad}}

def check_cwlog_kms(sess, resource_id, region):
    logs = client(sess, "logs", region)
    bad  = [lg["logGroupName"] for lg in logs.describe_log_groups().get("logGroups",[])
            if not lg.get("kmsKeyId")]
    return {"status": not bad, "details": {"unencrypted_log_groups": bad}}

def check_cwlog_retention(sess, resource_id, region):
    logs = client(sess, "logs", region)
    bad  = [{"logGroup":lg["logGroupName"],"retention":lg.get("retentionInDays")}
            for lg in logs.describe_log_groups().get("logGroups",[])
            if not lg.get("retentionInDays") or lg["retentionInDays"] > CW_RETENTION_DAYS]
    return {"status": not bad, "details": {"bad_retention_log_groups": bad}}

def check_cloudformation_termination(sess, resource_id, region):
    cf  = client(sess, "cloudformation", region)
    bad = [s["StackName"] for s in cf.describe_stacks()["Stacks"]
           if not s.get("EnableTerminationProtection")]
    return {"status": not bad, "details": {"no_tp_stacks": bad}}

def get_password_policy(sess, region):
    iam = client(sess, "iam", region)
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError:
        return {}

def make_not_impl(name):
    def fn(sess, rid, region):
        return {"status": False, "details": f"{name} not implemented"}
    return fn

# ─────────── Stub titles ───────────
STUB_TITLES = [
    "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
    "Check if S3 buckets have Object-level logging for read events is enabled in CloudTrail.",
    "Ensure a log metric filter and alarm exist for AWS Config configuration changes.",
    "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures.",
    "Ensure a log metric filter and alarm exist for AWS Organizations changes.",
    "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL).",
    "Ensure a log metric filter and alarm exist for changes to network gateways.",
    "Ensure a log metric filter and alarm exist for CloudTrail configuration changes.",
    "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created KMS CMKs.",
    "Ensure a log metric filter and alarm exist for IAM policy changes.",
    "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA.",
    "Ensure a log metric filter and alarm exist for route table changes.",
    "Ensure a log metric filter and alarm exist for S3 bucket policy changes.",
    "Ensure a log metric filter and alarm exist for security group changes.",
    "Ensure a log metric filter and alarm exist for unauthorized API calls.",
    "Ensure a log metric filter and alarm exist for usage of root account.",
    "Ensure a log metric filter and alarm exist for VPC changes.",
    "Ensure all VPC has public and private subnets defined",
    "Ensure all VPCs have Network Firewall enabled",
    "Ensure there are VPCs in more than one region",
    "Ensure VPC Flow Logging is Enabled in all VPCs.",
    "Ensure VPC subnets do not assign public IP by default",
    "Maintain different contact details to security, billing and operations.",
    "Resource Explorer Indexes Found",
    "Check if ACM certificates have Certificate Transparency logging enabled",
    "Check if API Gateway public endpoint has an authorizer configured.",
    "Check if API Gateway Stage has a WAF ACL attached.",
    "Check if API Gateway Stage has client certificate enabled to access your backend endpoint.",
    "Check if API Gateway Stage has logging enabled.",
    "Check if CloudFront distributions are set to HTTPS.",
    "Check if CloudFront distributions are using deprecated SSL protocols.",
    "Check if CloudFront distributions are using WAF.",
    "Check if CloudFront distributions have Field Level Encryption enabled.",
    "Check if CloudFront distributions have logging enabled.",
    "Check if Amazon Elasticsearch/Opensearch Service domains have internal user database enabled",
    "Check if Amazon Elasticsearch/Opensearch Service domains have logging enabled",
    "Check if Amazon Elasticsearch/Opensearch Service domains have updates available",
    "Check if EBS snapshots exists.",
    "Check if EC2 instances are managed by Systems Manager.",
    "Check if Elastic Load Balancers have logging enabled.",
    "Check if RDS instances has enhanced monitoring enabled.",
    "Check if RDS instances have multi-AZ enabled.",
    "Check if RDS instances is integrated with CloudWatch Logs.",
    "Check EC2 Instances older than specific days.",
    "Check for EC2 Instances with Public IP.",
    "Check for internet facing EC2 instances with Instance Profiles attached.",
    "Check whether the Application Load Balancer is configured with strictest desync mitigation mode, if not check if at least is configured with the drop_invalid_header_fields attribute",
    "Ensure there are no Security Groups not being used.",
    "Ensure that there is at least one AWS Backup plan"
]

# ─────────── BUILD VALIDATORS ───────────
VALIDATORS = {
    # critical / high
    "Check S3 Account Level Public Access Block":            check_s3_pab,
    "Ensure IAM Roles do not have AdministratorAccess policy attached": check_iam_admin_roles,
    "Ensure there are no SNS Topics unencrypted":            check_sns_unencrypted,
    "Find secrets in Lambda functions variables.":           check_lambda_secrets,
    "Check if ACM Certificates are about to expire in specific days or less": check_acm_expiry,
    "Ensure IAM Service Roles prevents against a cross-service confused deputy attack": check_service_role_trust,
    "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to any port.": check_sg_wide_open,
    "Ensure no security groups allow ingress from wide-open non-RFC1918 address.": check_sg_non_rfc1918,
    "Find secrets in EC2 User Data.":                        check_ec2_userdata,
    "Check if Amazon Elasticsearch/Opensearch Service domains has Amazon Cognito authentication for Kibana enabled": check_opensearch_cognito,
    "Check if EFS have policies which allow access to everyone": check_efs_everyone,
    "Check if RDS instances client connections are encrypted (Microsoft SQL Server and PostgreSQL).": check_rds_force_ssl,
    "Ensure only hardware MFA is enabled for the root account": check_root_hardware_mfa,
    "Check if secrets exists in ECS task definitions environment variables": check_ecs_task_secrets,

    # additional moderate/low
    "Check if CloudWatch log groups are protected by AWS KMS.":       check_cwlog_kms,
    "Check if CloudWatch Log Groups have a retention policy of specific days.":  check_cwlog_retention,
    "Enable termination protection for Cloudformation Stacks":         check_cloudformation_termination,
    "Ensure AWS Backup vaults exist":                                 check_backup_vaults_exist,
    "Ensure CloudTrail logs are encrypted at rest using KMS CMKs":   check_cloudtrail_logs_encrypted,
    "Ensure CloudTrail trails are integrated with CloudWatch Logs":   check_cloudtrail_trails_cwl,

    # IAM password policy
    "Ensure IAM password policy expires passwords within 90 days or less": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("MaxPasswordAge",999)<=90, "details": v}
    )[1],
    "Ensure IAM password policy prevents password reuse: 24 or greater": lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("PasswordReusePrevention",0)>=24, "details": v}
    )[1],
    "Ensure IAM password policy require at least one lowercase letter":  lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("RequireLowercaseCharacters",False), "details": v}
    )[1],
    "Ensure IAM password policy require at least one number":            lambda s,r,reg: (
        (v:=get_password_policy(s,reg)),
        {"status": v.get("RequireNumbers",False), "details": v}
    )[1],
    "Ensure IAM password policy require at least one symbol":            lambda s,r,reg: (
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

# add the stubs last
for title in STUB_TITLES:
    VALIDATORS[title] = make_not_impl(title)

# sanity check
if len(VALIDATORS) != 14 + 6 + 7 + len(STUB_TITLES):  # adjust if you add more
    print(f"⚠️  You have {len(VALIDATORS)} validators.")

# ─────────── Report loader & main ───────────
def load_report(path, severities):
    data = json.load(open(path))
    out = []
    for i in data:
        title = i.get("CheckTitle")
        sev   = i.get("Severity","").lower()
        if sev in severities and title in VALIDATORS:
            out.append({
                "profile":     i.get("Profile"),
                "account_id":  i.get("AccountId"),
                "region":      i.get("Region"),
                "title":       title,
                "resource_id": i.get("ResourceId")
            })
    return out

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--report",   required=True, help="Path to Prowler JSON")
    p.add_argument("--severity", nargs="+",
                   default=["critical","high","moderate","low"],
                   help="Severities to include")
    args = p.parse_args()

    findings = load_report(args.report, set([s.lower() for s in args.severity]))
    rows = []
    for f in findings:
        sess = boto3.Session(profile_name=f["profile"], region_name=f["region"])
        fn   = VALIDATORS[f["title"]]
        try:
            res = fn(sess, f["resource_id"], f["region"])
        except Exception as e:
            res = {"status": False, "details": str(e)}

        tp = classify_tp(res["status"], res["details"])
        det_str = (res["details"] if isinstance(res["details"],str)
                   else json.dumps(res["details"]))

        rows.append({
            "profile":       f["profile"],
            "account_id":    f"'{f['account_id']}",
            "region":        f["region"],
            "check_title":   f["title"],
            "resource_id":   f["resource_id"],
            "status":        "PASS" if res["status"] else "FAIL",
            "details":       det_str,
            "true_positive": tp
        })

    pd.DataFrame(rows).to_csv(OUTPUT_CSV, index=False)
    print(f"✅ Results written to {OUTPUT_CSV}")

if __name__=="__main__":
    main()
