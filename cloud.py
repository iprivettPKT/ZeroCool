"""Cloud recon module for ZeroCool.

A data-driven catalog of cloud enumeration commands across AWS, Azure, GCP,
M365/Entra and multi-cloud asset discovery. Built from a Keyword (company) and
Domain bar plus per-action inputs (profile, region, bucket, tenant, creds).
Same pattern as the AD/Web modules: read context -> build command -> run via the
runner (or send into a shell / route through proxychains).
"""

from __future__ import annotations

import shlex

from flask import Blueprint, jsonify, render_template, request

import storage
import tools

cloud_bp = Blueprint("cloud", __name__)


def _q(v: str) -> str:
    return shlex.quote(v) if v else ""


def cmd(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def pv(ctx: dict, name: str, default: str = "") -> str:
    return (ctx["p"].get(name) or "").strip() or default


def prof(ctx: dict) -> str:
    p = pv(ctx, "profile", "")
    return f"--profile {_q(p)}" if p else ""


def build_context(params: dict, eng: dict) -> dict:
    return {
        "keyword": (params.get("keyword") or eng.get("client") or "company").strip(),
        "domain": (params.get("domain") or eng.get("domain") or "target.com").strip(),
        "loot": (eng.get("output_dir") or "").strip(),
        "proxychains": str(params.get("proxychains", "")).lower() in ("1", "true", "on", "yes"),
        "p": params,
    }


# --- AWS ---
def b_aws_whoami(ctx): return cmd("aws sts get-caller-identity", prof(ctx))
def b_aws_iam(ctx): return cmd("aws iam list-users", prof(ctx), "; aws iam list-roles", prof(ctx))
def b_aws_s3_own(ctx): return cmd("aws s3 ls", prof(ctx))
def b_aws_s3_anon(ctx):
    b = pv(ctx, "bucket", ctx["keyword"])
    return cmd("aws s3 ls", f"s3://{b}", "--no-sign-request")
def b_aws_ec2(ctx):
    return cmd("aws ec2 describe-instances", prof(ctx),
               ("--region " + _q(pv(ctx, "region", "us-east-1"))))
def b_aws_enum_iam(ctx):
    return cmd("enumerate-iam --access-key", _q(pv(ctx, "access_key", "AKIA...")),
               "--secret-key", _q(pv(ctx, "secret_key", "...")))
def b_scout_aws(ctx): return cmd("scout aws", prof(ctx))
def b_prowler_aws(ctx): return cmd("prowler aws", ("-p " + _q(pv(ctx, "profile", ""))) if pv(ctx, "profile") else "")
def b_s3scanner(ctx): return cmd("s3scanner scan -bucket", _q(pv(ctx, "bucket", ctx["keyword"])))


# --- Azure ---
def b_az_whoami(ctx): return "az account show"
def b_az_accounts(ctx): return "az account list -o table"
def b_az_users(ctx): return "az ad user list -o table"
def b_az_resources(ctx): return "az resource list -o table"
def b_az_vms(ctx): return "az vm list -d -o table"
def b_az_storage(ctx): return "az storage account list -o table"
def b_azurehound(ctx):
    return cmd("azurehound -u", _q(pv(ctx, "user", "user@" + ctx["domain"])),
               "-p", _q(pv(ctx, "password", "PASSWORD")),
               "list --tenant", _q(pv(ctx, "tenant", ctx["domain"])), "-o azurehound.json")
def b_roadrecon(ctx):
    return cmd("roadrecon auth -u", _q(pv(ctx, "user", "user@" + ctx["domain"])),
               "-p", _q(pv(ctx, "password", "PASSWORD")), "&& roadrecon gather")


# --- GCP ---
def b_gcp_whoami(ctx): return "gcloud auth list; gcloud config list"
def b_gcp_projects(ctx): return "gcloud projects list"
def b_gcp_instances(ctx): return "gcloud compute instances list"
def b_gcp_iam(ctx): return cmd("gcloud projects get-iam-policy", _q(pv(ctx, "project", "PROJECT_ID")))
def b_gcp_buckets(ctx): return "gsutil ls"
def b_gcp_bucketbrute(ctx): return cmd("gcpbucketbrute.py -k", _q(ctx["keyword"]), "-u")
def b_scout_gcp(ctx): return "scout gcp --user-account"


# --- M365 / Entra ---
def b_o365_tenant(ctx):
    return cmd("curl -s", _q(f"https://login.microsoftonline.com/{ctx['domain']}/.well-known/openid-configuration"))
def b_o365_realm(ctx):
    return cmd("curl -s", _q(f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{ctx['domain']}&xml=1"))
def b_o365spray_validate(ctx): return cmd("o365spray --validate --domain", _q(ctx["domain"]))
def b_o365spray_enum(ctx):
    return cmd("o365spray --enum -U", _q(pv(ctx, "userfile", "users.txt")), "--domain", _q(ctx["domain"]))
def b_aadint_recon(ctx):
    return cmd("pwsh -c", _q(f"Import-Module AADInternals; Invoke-AADIntReconAsOutsider -DomainName {ctx['domain']}"))
def b_teamfiltration(ctx):
    return cmd("TeamFiltration --outsider --domain", _q(ctx["domain"]))


# --- Multi-cloud / assets ---
def b_cloud_enum(ctx): return cmd("cloud_enum -k", _q(ctx["keyword"]))
def b_subfinder(ctx): return cmd("subfinder -silent -d", _q(ctx["domain"]))
def b_amass(ctx): return cmd("amass enum -passive -d", _q(ctx["domain"]))


I = lambda name, label, ph="", default="": {"name": name, "label": label, "placeholder": ph, "default": default}
PROFILE = I("profile", "AWS profile", "default")
BUCKET = I("bucket", "Bucket name", "company-backups")

ACTIONS = [
    dict(id="aws_whoami", cat="AWS", label="Caller identity", desc="Who am I (sts get-caller-identity).", build=b_aws_whoami, inputs=[PROFILE]),
    dict(id="aws_iam", cat="AWS", label="IAM users & roles", desc="List IAM users and roles.", build=b_aws_iam, inputs=[PROFILE]),
    dict(id="aws_s3_own", cat="AWS", label="List own S3 buckets", desc="Buckets the creds can see.", build=b_aws_s3_own, inputs=[PROFILE]),
    dict(id="aws_s3_anon", cat="AWS", label="Anonymous S3 bucket", desc="List a bucket unauthenticated.", build=b_aws_s3_anon, inputs=[BUCKET]),
    dict(id="aws_ec2", cat="AWS", label="EC2 instances", desc="Describe EC2 instances.", build=b_aws_ec2, inputs=[PROFILE, I("region", "Region", "us-east-1", "us-east-1")]),
    dict(id="aws_enum_iam", cat="AWS", label="enumerate-iam", desc="Brute IAM permissions from keys.", build=b_aws_enum_iam,
         inputs=[I("access_key", "Access key", "AKIA..."), I("secret_key", "Secret key", "")]),
    dict(id="scout_aws", cat="AWS", label="ScoutSuite (AWS)", desc="Full security posture audit.", build=b_scout_aws, inputs=[PROFILE]),
    dict(id="prowler_aws", cat="AWS", label="Prowler (AWS)", desc="CIS / best-practice checks.", build=b_prowler_aws, inputs=[PROFILE]),
    dict(id="s3scanner", cat="AWS", label="S3Scanner", desc="Find & enumerate a bucket.", build=b_s3scanner, inputs=[BUCKET]),

    dict(id="az_whoami", cat="Azure", label="Account show", desc="Current Azure account.", build=b_az_whoami),
    dict(id="az_accounts", cat="Azure", label="List subscriptions", desc="Subscriptions in reach.", build=b_az_accounts),
    dict(id="az_users", cat="Azure", label="Entra users", desc="List directory users.", build=b_az_users),
    dict(id="az_resources", cat="Azure", label="Resources", desc="List all resources.", build=b_az_resources),
    dict(id="az_vms", cat="Azure", label="Virtual machines", desc="List VMs with details.", build=b_az_vms),
    dict(id="az_storage", cat="Azure", label="Storage accounts", desc="List storage accounts.", build=b_az_storage),
    dict(id="azurehound", cat="Azure", label="AzureHound", desc="BloodHound data for Azure.", build=b_azurehound,
         inputs=[I("user", "User", "user@domain"), I("password", "Password", ""), I("tenant", "Tenant", "")]),
    dict(id="roadrecon", cat="Azure", label="ROADrecon", desc="Entra ID recon & gather.", build=b_roadrecon,
         inputs=[I("user", "User", "user@domain"), I("password", "Password", "")]),

    dict(id="gcp_whoami", cat="GCP", label="Auth & config", desc="Active account and config.", build=b_gcp_whoami),
    dict(id="gcp_projects", cat="GCP", label="Projects", desc="List projects.", build=b_gcp_projects),
    dict(id="gcp_instances", cat="GCP", label="Compute instances", desc="List GCE instances.", build=b_gcp_instances),
    dict(id="gcp_iam", cat="GCP", label="IAM policy", desc="Project IAM bindings.", build=b_gcp_iam, inputs=[I("project", "Project ID", "")]),
    dict(id="gcp_buckets", cat="GCP", label="Storage buckets", desc="List GCS buckets.", build=b_gcp_buckets),
    dict(id="gcp_bucketbrute", cat="GCP", label="GCPBucketBrute", desc="Brute GCS bucket names from keyword.", build=b_gcp_bucketbrute),
    dict(id="scout_gcp", cat="GCP", label="ScoutSuite (GCP)", desc="GCP posture audit.", build=b_scout_gcp),

    dict(id="o365_tenant", cat="M365 / Entra", label="Tenant OpenID config", desc="Tenant ID & endpoints (no auth).", build=b_o365_tenant),
    dict(id="o365_realm", cat="M365 / Entra", label="User realm", desc="Is the domain managed/federated?", build=b_o365_realm),
    dict(id="o365spray_validate", cat="M365 / Entra", label="o365spray validate", desc="Validate the domain uses O365.", build=b_o365spray_validate),
    dict(id="o365spray_enum", cat="M365 / Entra", label="o365spray user enum", desc="Enumerate valid users.", build=b_o365spray_enum, inputs=[I("userfile", "Users file", "users.txt", "users.txt")]),
    dict(id="aadint_recon", cat="M365 / Entra", label="AADInternals recon", desc="Outsider recon of the tenant.", build=b_aadint_recon),
    dict(id="teamfiltration", cat="M365 / Entra", label="TeamFiltration", desc="O365 enum / spray / exfil.", build=b_teamfiltration),

    dict(id="cloud_enum", cat="Multi-cloud", label="cloud_enum", desc="Public AWS/Azure/GCP assets from a keyword.", build=b_cloud_enum),
    dict(id="subfinder", cat="Multi-cloud", label="subfinder", desc="Passive subdomain discovery.", build=b_subfinder),
    dict(id="amass", cat="Multi-cloud", label="amass (passive)", desc="Passive asset/subdomain enum.", build=b_amass),
]

ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}


def serializable_catalog():
    return [{"id": a["id"], "cat": a["cat"], "label": a["label"], "desc": a["desc"],
             "inputs": a.get("inputs", [])} for a in ACTIONS]


@cloud_bp.route("/cloud")
def cloud():
    eng = storage.load_engagement()
    catalog = serializable_catalog()
    cats = []
    for a in catalog:
        if a["cat"] not in cats:
            cats.append(a["cat"])
    return render_template("cloud.html", eng=eng, catalog=catalog, categories=cats)


@cloud_bp.route("/cloud/build", methods=["POST"])
def cloud_build():
    payload = request.get_json(silent=True) or {}
    action = ACTIONS_BY_ID.get(payload.get("action_id"))
    if not action:
        return jsonify({"error": "unknown action"}), 400
    eng = storage.load_engagement()
    ctx = build_context(payload.get("params", {}), eng)
    command = action["build"](ctx)
    if ctx["proxychains"]:
        command = tools.proxychains_prefix() + command
    return jsonify({"command": command, "warnings": [], "label": action["label"]})
