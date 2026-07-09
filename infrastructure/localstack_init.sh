#!/usr/bin/env bash
# Runs inside LocalStack on startup — creates the S3 bucket, SNS topic,
# and CloudWatch log group used by the ai-consumer.
set -e

REGION="us-east-1"
BUCKET="guardstream-alerts"
TOPIC="guardstream-attacks"

echo "[localstack-init] Creating S3 bucket: $BUCKET"
awslocal s3 mb "s3://$BUCKET" --region "$REGION"

awslocal s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET" \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-old-alerts",
      "Status": "Enabled",
      "Filter": {"Prefix": "alerts/"},
      "Expiration": {"Days": 90}
    }]
  }'

echo "[localstack-init] Creating SNS topic: $TOPIC"
TOPIC_ARN=$(awslocal sns create-topic --name "$TOPIC" --region "$REGION" \
  --query TopicArn --output text)

echo "[localstack-init] Creating CloudWatch log group"
awslocal logs create-log-group --log-group-name "/guardstream/ai-consumer" \
  --region "$REGION" 2>/dev/null || true

echo "[localstack-init] Done."
echo "  S3 bucket : s3://$BUCKET"
echo "  SNS topic : $TOPIC_ARN"
echo "  Set in docker-compose:"
echo "    S3_BUCKET=$BUCKET"
echo "    SNS_TOPIC_ARN=$TOPIC_ARN"
