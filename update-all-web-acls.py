import boto3
import argparse
import json
import os
from datetime import datetime


def get_client(scope, profile, region):
    session = boto3.Session(profile_name=profile, region_name=region if scope == "REGIONAL" else "us-east-1")
    return session.client("wafv2")


def list_web_acls(waf_client, scope):
    web_acls = []
    next_marker = None
    while True:
        kwargs = {"Scope": scope}
        if next_marker:
            kwargs["NextMarker"] = next_marker
        response = waf_client.list_web_acls(**kwargs)
        web_acls.extend(response["WebACLs"])
        next_marker = response.get("NextMarker")
        if not next_marker:
            break
    return web_acls


def convert_bytes(obj):
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: convert_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_bytes(i) for i in obj]
    return obj


def download_acl(waf_client, name, id, scope, outdir="backups"):
    os.makedirs(outdir, exist_ok=True)
    response = waf_client.get_web_acl(Name=name, Id=id, Scope=scope)
    with open(f"{outdir}/{name}_{datetime.now().isoformat()}.json", "w") as f:
        json.dump(convert_bytes(response), f, indent=2)
    return response


def modify_rule_group(rule):
    # Modify only AWS-AWSManagedRulesCommonRuleSet
    statement = rule.get("Statement", {}).get("ManagedRuleGroupStatement")
    if statement and statement["Name"] == "AWSManagedRulesCommonRuleSet":
        print(f"  → Updating rule: {rule['Name']}")
        rule["Statement"]["ManagedRuleGroupStatement"]["ScopeDownStatement"] = {
            "NotStatement": {
                "Statement": {
                    "AndStatement": {
                        "Statements": [
                            {
                                "ByteMatchStatement": {
                                    "SearchString": "AWSALB",
                                    "FieldToMatch": {
                                        "Cookies": {
                                            "MatchPattern": {
                                                "IncludedCookies": ["AWSALB"]
                                            },
                                            "MatchScope": "KEY",
                                            "OversizeHandling": "NO_MATCH"
                                        }
                                    },
                                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                    "PositionalConstraint": "EXACTLY"
                                }
                            },
                            {
                                "ByteMatchStatement": {
                                    "SearchString": "AWSALBCORS",
                                    "FieldToMatch": {
                                        "Cookies": {
                                            "MatchPattern": {
                                                "IncludedCookies": ["AWSALBCORS"]
                                            },
                                            "MatchScope": "KEY",
                                            "OversizeHandling": "NO_MATCH"
                                        }
                                    },
                                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                    "PositionalConstraint": "EXACTLY"
                                }
                            },
                            {
                                "ByteMatchStatement": {
                                    "SearchString": "SSESS",
                                    "FieldToMatch": {
                                        "Cookies": {
                                            "MatchPattern": {
                                                "All": {}
                                            },
                                            "MatchScope": "KEY",
                                            "OversizeHandling": "NO_MATCH"
                                        }
                                    },
                                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                    "PositionalConstraint": "STARTS_WITH"
                                }
                            }
                        ]
                    }
                }
            }
        }


def update_web_acl(waf_client, acl_summary, scope):
    name = acl_summary["Name"]
    id = acl_summary["Id"]
    print(f"\n📦 Processing WebACL: {name}")

    acl_data = download_acl(waf_client, name, id, scope)
    rules = acl_data["WebACL"]["Rules"]
    description = acl_data.get("Description") or "Updated via script"
    updated = False

    for rule in rules:
        if rule.get("Statement", {}).get("ManagedRuleGroupStatement", {}).get("Name") == "AWSManagedRulesCommonRuleSet":
            modify_rule_group(rule)
            updated = True

    if updated:
        print(f"  🔧 Updating WebACL: {name}")
        waf_client.update_web_acl(
            Name=name,
            Id=id,
            Scope=scope,
            DefaultAction=acl_data["WebACL"]["DefaultAction"],
            Description=description,
            Rules=rules,
            LockToken=acl_data["LockToken"],
            VisibilityConfig=acl_data["WebACL"]["VisibilityConfig"]
        )
    else:
        print("  ⚠️  No matching rule found to update.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, help="AWS CLI profile name")
    parser.add_argument("--region", required=False, help="AWS region (required for REGIONAL)")
    parser.add_argument("--scope", required=True, choices=["CLOUDFRONT", "REGIONAL"])
    parser.add_argument("--webacl-name", required=False, help="WebACL name to update (optional)")
    args = parser.parse_args()

    if args.scope == "REGIONAL" and not args.region:
        parser.error("--region is required when --scope is REGIONAL")

    waf_client = get_client(args.scope, args.profile, args.region)

    web_acls = list_web_acls(waf_client, args.scope)
    for acl in web_acls:
        if args.webacl_name and acl["Name"] != args.webacl_name:
            continue
        update_web_acl(waf_client, acl, args.scope)


if __name__ == "__main__":
    main()
