from aws_cdk import (
    Duration,
    Stack,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_lambda as _lambda,
)
from constructs import Construct


class AutoRemediationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # 修復処理を行うLambda
        remediate_fn = _lambda.Function(
            self,
            "RemediateFunction",
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="remediate.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(30),
        )

        # バケットポリシーの取得・更新と、ライフサイクル設定の更新のみ許可
        remediate_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetBucketPolicy",
                    "s3:PutBucketPolicy",
                    "s3:PutLifecycleConfiguration",
                ],
                resources=["arn:aws:s3:::*"],
            )
        )

        # Security Hub CSPMの検出結果のうち、S3.5とS3.13の失敗だけを拾う
        rule = events.Rule(
            self,
            "FailedS3ControlRule",
            event_pattern=events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"],
                detail={
                    "findings": {
                        "Compliance": {
                            "SecurityControlId": ["S3.5", "S3.13"],
                            "Status": ["FAILED"],
                        },
                        "Workflow": {"Status": ["NEW"]},
                        "RecordState": ["ACTIVE"],
                    }
                },
            ),
        )
        rule.add_target(targets.LambdaFunction(remediate_fn))
