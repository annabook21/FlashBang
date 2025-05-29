# FlashBang CLI Deployment Guide 🚀

This guide covers all the ways to deploy FlashBang honeypot using command-line interfaces.

## 🎯 Quick Reference

| Method | Complexity | Best For | Command |
|--------|------------|----------|---------|
| **Interactive Script** | ⭐ Easy | First-time users | `./deploy-flashbang.sh` |
| **One-liner** | ⭐⭐ Medium | Quick deployments | `aws cloudformation deploy...` |
| **Parameter File** | ⭐⭐⭐ Advanced | Production/CI/CD | `aws cloudformation deploy --parameter-overrides file://params.json` |
| **AWS CLI with variables** | ⭐⭐⭐ Advanced | Scripted deployments | Custom bash scripts |

## 🚀 Method 1: Interactive Deployment Script (Recommended)

**Best for:** First-time users, learning, guided deployments

```bash
# Clone repository
git clone https://github.com/your-org/flashbang-honeypot.git
cd flashbang-honeypot

# Make executable and run
chmod +x deploy-flashbang.sh
./deploy-flashbang.sh
```

**What it does:**
- ✅ Validates prerequisites automatically
- ✅ Shows available AWS resources interactively
- ✅ Guides parameter selection with helpful prompts
- ✅ Deploys with comprehensive error handling
- ✅ Performs post-deployment validation
- ✅ Displays all outputs and next steps

**Example output:**
```
🎯 FlashBang Honeypot Deployment Script
=======================================

[INFO] Checking prerequisites...
[SUCCESS] AWS CLI found and configured
[SUCCESS] CloudFormation template validated
[INFO] Gathering deployment parameters...

Available VPCs:
┌─────────────────────┬──────────────┬─────────────────┐
│ VpcId               │ Name         │ CidrBlock       │
├─────────────────────┼──────────────┼─────────────────┤
│ vpc-12345678        │ MyVPC        │ 10.0.0.0/16     │
└─────────────────────┴──────────────┴─────────────────┘

Enter VPC ID: vpc-12345678
...
[SUCCESS] 🎯 FlashBang Honeypot Deployed Successfully!
```

## ⚡ Method 2: One-Line Deployment

**Best for:** Quick deployments, experienced users, automation

```bash
aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name flashbang-honeypot \
  --parameter-overrides \
    MyVPC=vpc-12345678 \
    PublicSubnets=subnet-abc123,subnet-def456 \
    PrivateSubnet=subnet-ghi789 \
    KeyName=my-key-pair \
    EnableDirectSSH=false \
    NotificationEmail=admin@example.com \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

**With environment variables:**
```bash
# Set your parameters
export VPC_ID="vpc-12345678"
export PUBLIC_SUBNETS="subnet-abc123,subnet-def456"
export PRIVATE_SUBNET="subnet-ghi789"
export KEY_NAME="my-key-pair"
export EMAIL="admin@example.com"

# Deploy
aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name flashbang-honeypot \
  --parameter-overrides \
    MyVPC=$VPC_ID \
    PublicSubnets=$PUBLIC_SUBNETS \
    PrivateSubnet=$PRIVATE_SUBNET \
    KeyName=$KEY_NAME \
    EnableDirectSSH=false \
    NotificationEmail=$EMAIL \
  --capabilities CAPABILITY_NAMED_IAM
```

## 📄 Method 3: Parameter File Deployment

**Best for:** Production deployments, CI/CD pipelines, version control

1. **Create parameter file:**
```bash
cat > parameters.json << EOF
[
  {
    "ParameterKey": "MyVPC",
    "ParameterValue": "vpc-12345678"
  },
  {
    "ParameterKey": "PublicSubnets",
    "ParameterValue": "subnet-abc123,subnet-def456"
  },
  {
    "ParameterKey": "PrivateSubnet",
    "ParameterValue": "subnet-ghi789"
  },
  {
    "ParameterKey": "KeyName",
    "ParameterValue": "my-key-pair"
  },
  {
    "ParameterKey": "EnableDirectSSH",
    "ParameterValue": "false"
  },
  {
    "ParameterKey": "NotificationEmail",
    "ParameterValue": "admin@example.com"
  },
  {
    "ParameterKey": "HoneypotMode",
    "ParameterValue": "medium"
  },
  {
    "ParameterKey": "EnableS3LogBackup",
    "ParameterValue": "true"
  },
  {
    "ParameterKey": "EnableCloudWatchLogs",
    "ParameterValue": "true"
  }
]
EOF
```

2. **Deploy with parameter file:**
```bash
aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name flashbang-honeypot \
  --parameter-overrides file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM
```

## 🔧 Method 4: Advanced Scripted Deployment

**Best for:** Custom automation, complex environments, multi-stack deployments

```bash
#!/bin/bash
# advanced-deploy.sh

set -e

# Configuration
STACK_NAME="flashbang-honeypot"
REGION="us-east-1"
TEMPLATE_FILE="v2.yaml"

# Get AWS account info
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Deploying to AWS Account: $ACCOUNT_ID"

# Validate template
echo "Validating CloudFormation template..."
aws cloudformation validate-template --template-body file://$TEMPLATE_FILE

# Get default VPC if not specified
if [ -z "$VPC_ID" ]; then
  VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text)
  echo "Using default VPC: $VPC_ID"
fi

# Get subnets automatically
PUBLIC_SUBNETS=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=map-public-ip-on-launch,Values=true" \
  --query 'Subnets[0:2].SubnetId' \
  --output text | tr '\t' ',')

PRIVATE_SUBNET=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=map-public-ip-on-launch,Values=false" \
  --query 'Subnets[0].SubnetId' \
  --output text)

echo "Public Subnets: $PUBLIC_SUBNETS"
echo "Private Subnet: $PRIVATE_SUBNET"

# Deploy stack
aws cloudformation deploy \
  --template-file $TEMPLATE_FILE \
  --stack-name $STACK_NAME \
  --parameter-overrides \
    MyVPC=$VPC_ID \
    PublicSubnets=$PUBLIC_SUBNETS \
    PrivateSubnet=$PRIVATE_SUBNET \
    KeyName=${KEY_NAME:-"default-key"} \
    EnableDirectSSH=false \
    NotificationEmail=${EMAIL:-""} \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION

# Get outputs
echo "Deployment complete! Getting outputs..."
aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].Outputs' \
  --output table
```

## 🔍 Post-Deployment Validation

After any deployment method, validate your honeypot:

```bash
# Get stack outputs
aws cloudformation describe-stacks \
  --stack-name flashbang-honeypot \
  --query 'Stacks[0].Outputs' \
  --output table

# Test the honeypot
ALB_URL=$(aws cloudformation describe-stacks \
  --stack-name flashbang-honeypot \
  --query 'Stacks[0].Outputs[?OutputKey==`FlashBangURL`].OutputValue' \
  --output text)

echo "Testing honeypot at: $ALB_URL"
curl -s $ALB_URL | head -5
curl -s $ALB_URL/admin
curl -s $ALB_URL/.env

# Access instance via Session Manager
INSTANCE_ID=$(aws cloudformation describe-stacks \
  --stack-name flashbang-honeypot \
  --query 'Stacks[0].Outputs[?OutputKey==`FlashBangInstanceId`].OutputValue' \
  --output text)

echo "Access instance with: aws ssm start-session --target $INSTANCE_ID"

# Monitor logs
echo "Monitor logs with: aws logs tail /aws/ec2/flashbang-honeypot/flashbang --follow"
```

## 🛠️ Troubleshooting CLI Deployments

### Common Issues and Solutions

**1. Template validation errors:**
```bash
# Validate template syntax
aws cloudformation validate-template --template-body file://v2.yaml

# Check for linting issues
pip install cfn-lint
cfn-lint v2.yaml
```

**2. Parameter validation errors:**
```bash
# Check VPC exists
aws ec2 describe-vpcs --vpc-ids vpc-12345678

# Check subnets exist and are in correct VPC
aws ec2 describe-subnets --subnet-ids subnet-abc123 subnet-def456

# Check key pair exists
aws ec2 describe-key-pairs --key-names my-key-pair
```

**3. Permission errors:**
```bash
# Check current AWS identity
aws sts get-caller-identity

# Test CloudFormation permissions
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE
```

**4. Stack deployment failures:**
```bash
# Check stack events for errors
aws cloudformation describe-stack-events --stack-name flashbang-honeypot

# Get detailed error information
aws cloudformation describe-stack-resources --stack-name flashbang-honeypot
```

## 🔄 Stack Management Commands

**Update stack:**
```bash
aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name flashbang-honeypot \
  --parameter-overrides file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM
```

**Delete stack:**
```bash
aws cloudformation delete-stack --stack-name flashbang-honeypot

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name flashbang-honeypot
```

**Check stack status:**
```bash
aws cloudformation describe-stacks \
  --stack-name flashbang-honeypot \
  --query 'Stacks[0].StackStatus' \
  --output text
```

## 📊 Monitoring Commands

**View CloudWatch logs:**
```bash
# List log groups
aws logs describe-log-groups --log-group-name-prefix "/aws/ec2/flashbang"

# Tail logs in real-time
aws logs tail /aws/ec2/flashbang-honeypot/flashbang --follow

# Query logs
aws logs start-query \
  --log-group-name "/aws/ec2/flashbang-honeypot/flashbang" \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, @message | filter @message like /attack/'
```

**Check instance health:**
```bash
INSTANCE_ID=$(aws cloudformation describe-stacks \
  --stack-name flashbang-honeypot \
  --query 'Stacks[0].Outputs[?OutputKey==`FlashBangInstanceId`].OutputValue' \
  --output text)

# Instance status
aws ec2 describe-instance-status --instance-ids $INSTANCE_ID

# System logs
aws ec2 get-console-output --instance-id $INSTANCE_ID
```

## 🎯 Pro Tips

1. **Use AWS profiles for multiple environments:**
```bash
aws cloudformation deploy --profile production --template-file v2.yaml ...
```

2. **Enable debug mode for troubleshooting:**
```bash
export AWS_CLI_DEBUG=1
./deploy-flashbang.sh
```

3. **Use parameter validation:**
```bash
# Validate parameters before deployment
aws cloudformation validate-template \
  --template-body file://v2.yaml \
  --parameters file://parameters.json
```

4. **Save deployment commands in scripts:**
```bash
# Create reusable deployment script
cat > deploy-prod.sh << 'EOF'
#!/bin/bash
aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name flashbang-prod \
  --parameter-overrides file://prod-parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
EOF
chmod +x deploy-prod.sh
```

5. **Use CloudFormation change sets for safe updates:**
```bash
# Create change set
aws cloudformation create-change-set \
  --stack-name flashbang-honeypot \
  --template-body file://v2.yaml \
  --change-set-name update-$(date +%Y%m%d-%H%M%S) \
  --capabilities CAPABILITY_NAMED_IAM

# Review changes before applying
aws cloudformation describe-change-set \
  --stack-name flashbang-honeypot \
  --change-set-name update-20241201-143000

# Execute change set
aws cloudformation execute-change-set \
  --stack-name flashbang-honeypot \
  --change-set-name update-20241201-143000
```

---

## 📚 Additional Resources

- **Main README**: `README.md` - Complete documentation
- **Deployment Checklist**: `DEPLOYMENT_CHECKLIST.md` - Pre-deployment validation
- **Dynamic IP Solutions**: `DYNAMIC_IP_SOLUTIONS.md` - IP address handling
- **Deployment Improvements**: `DEPLOYMENT_IMPROVEMENTS_SUMMARY.md` - Recent enhancements

**Need help?** Run the interactive script with `./deploy-flashbang.sh` - it handles most edge cases automatically! 