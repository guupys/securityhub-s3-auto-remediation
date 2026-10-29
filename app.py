import aws_cdk as cdk

from auto_remediation_stack import AutoRemediationStack

app = cdk.App()
AutoRemediationStack(app, "SecurityHubAutoRemediationStack")
app.synth()
