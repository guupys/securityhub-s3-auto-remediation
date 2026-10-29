import json

import boto3
from botocore.exceptions import ClientError

# S3.13で設定するライフサイクルルール
# 128KBより大きいオブジェクトを30日後にIntelligent-Tieringへ移行 (削除はしない)
LIFECYCLE_RULE = {
    "ID": "S3.13 auto remediation",
    "Status": "Enabled",
    "Filter": {"ObjectSizeGreaterThan": 131072},
    "Transitions": [{"Days": 30, "StorageClass": "INTELLIGENT_TIERING"}],
}


def remediate_s3_5(s3, bucket, partition):
    """S3.5: HTTPリクエストを拒否するステートメントをバケットポリシーに追記"""
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
        # ポリシーが無ければ新しく作る
        policy = {"Id": "BucketPolicy", "Version": "2012-10-17", "Statement": []}

    # 追記済みなら何もしない (S3はSidの重複を受け付けるため、確認しないと同じステートメントが並ぶ)
    if any(s.get("Sid") == "AllowSSLRequestsOnly" for s in policy["Statement"]):
        return "skipped (already exists)"

    # 既存のステートメントは残したまま追記する
    policy["Statement"].append(
        {
            "Sid": "AllowSSLRequestsOnly",
            "Action": "s3:*",
            "Effect": "Deny",
            "Resource": [
                f"arn:{partition}:s3:::{bucket}",
                f"arn:{partition}:s3:::{bucket}/*",
            ],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            "Principal": "*",
        }
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return "remediated"


def remediate_s3_13(s3, bucket, partition):
    """S3.13: ライフサイクル設定を上書きする"""
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={"Rules": [LIFECYCLE_RULE]},
    )
    return "remediated"


# コントロールIDと修復処理の対応。他のコントロールを追加する場合はここに足す
REMEDIATIONS = {
    "S3.5": remediate_s3_5,
    "S3.13": remediate_s3_13,
}


def handler(event, context):
    for finding in event["detail"]["findings"]:
        control_id = finding["Compliance"]["SecurityControlId"]
        remediate = REMEDIATIONS.get(control_id)
        if remediate is None:
            continue

        for resource in finding["Resources"]:
            if resource["Type"] != "AwsS3Bucket":
                continue
            # リソースIDは arn:<パーティション>:s3:::<バケット名> の形式
            partition = resource["Id"].split(":")[1]
            bucket = resource["Id"].split(":::")[-1]
            s3 = boto3.client("s3", region_name=resource.get("Region"))
            result = remediate(s3, bucket, partition)
            print(json.dumps({"control": control_id, "bucket": bucket, "result": result}))
