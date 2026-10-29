# securityhub-auto-remediation

Security Hub CSPMで不合格 (`FAILED`) になったS3のコントロールを、Amazon EventBridgeとAWS Lambdaで自動修復するAWS CDK (Python) のコード。

解説記事: [【コツコツAWS】Security Hubの検出結果に対するS3の自動修復](https://qiita.com/guupys/items/bab114cc96c8144e5cca)

## 修復するコントロール

| コントロール | 内容 | 修復内容 |
| --- | --- | --- |
| S3.5 | バケットポリシーでSSL (HTTPS) を必須にする | HTTPのリクエストを拒否するステートメント (`AllowSSLRequestsOnly`) をバケットポリシーに追加する。 |
| S3.13 | ライフサイクル設定を構成する | 128KBより大きいオブジェクトを、30日後にS3 Intelligent-Tieringへ移すルールを設定する |

## 構成

```
Security Hub CSPM (S3.5 / S3.13 が FAILED)
  → EventBridgeルール (Security Hub Findings - Imported)
  → Lambda (バケットポリシー / ライフサイクル設定を更新)
```

## 前提

- Security Hub CSPMが有効で、S3.5とS3.13が評価されていること
- AWS CDK v2とPython 3がインストールされていること
- デプロイ先のアカウントとリージョンでCDKのブートストラップが済んでいること

## 注意

- **S3.13の修復は、既存のライフサイクル設定を上書きします。** 設定済みのルールがあるバケットでは、そのルールが消えます。
- 修復の対象はアカウント内の全バケットです。
