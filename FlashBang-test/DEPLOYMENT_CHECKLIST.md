# FlashBang Deployment Checklist & Validation Guide

This guide ensures your FlashBang honeypot CloudFormation template deploys successfully without issues.

## 🔍 Pre-Deployment Validation

### 1. Template Validation
```bash
# Validate CloudFormation template syntax
aws cloudformation validate-template --template-body file://v2.yaml

# Check for linting issues (requires cfn-lint)
pip install cfn-lint
cfn-lint v2.yaml
```

### 2. Prerequisites Check
```bash
# Check AWS CLI configuration
aws sts get-caller-identity

# Verify required permissions
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names cloudformation:CreateStack ec2:CreateVpc s3:CreateBucket \
  --resource-arns "*"

# Check service limits
aws service-quotas get-service-quota --service-code ec2 --quota-code L-1216C47A  # Running On-Demand instances
aws service-quotas get-service-quota --service-code elasticloadbalancing --quota-code L-53EA6B1F  # ALBs per region
```

### 3. Network Prerequisites
```bash
# Verify VPC exists and has required subnets
VPC_ID="vpc-xxxxxxxx"
aws ec2 describe-vpcs --vpc-ids $VPC_ID

# Check public subnets (minimum 2 in different AZs)
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available"

# Verify internet gateway attached
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID"
```

## 🛠️ Template Improvements

### 1. Add Parameter Validation
```yaml
# Add to Parameters section for better validation
Parameters:
  StackName:
    Type: String
    Description: Stack name for resource naming
    AllowedPattern: '^[a-zA-Z][a-zA-Z0-9-]*$'
    ConstraintDescription: Must start with a letter and contain only alphanumeric characters and hyphens
    
  PublicSubnets:
    Type: List<AWS::EC2::Subnet::Id>
    Description: List of public subnets for ALB (minimum 2 in different AZs)
    ConstraintDescription: Must select at least 2 subnets in different Availability Zones
```

### 2. Add Mappings for AMI IDs
```yaml
# Add region-specific AMI mappings
Mappings:
  RegionMap:
    us-east-1:
      AMI: ami-0df435f331839b2d6
    us-west-2:
      AMI: ami-0c2d3e23d757b5d84
    eu-west-1:
      AMI: ami-0c02fb55956c7d316
    ap-southeast-1:
      AMI: ami-0c802847a7dd848c0
```

### 3. Enhanced Error Handling
```yaml
# Add custom resource for validation
ValidationLambda:
  Type: AWS::Lambda::Function
  Properties:
    Runtime: python3.12
    Handler: index.handler
    Code:
      ZipFile: |
        import boto3
        import cfnresponse
        
        def handler(event, context):
            try:
                if event['RequestType'] == 'Create':
                    # Validate subnet AZs
                    ec2 = boto3.client('ec2')
                    subnets = event['ResourceProperties']['PublicSubnets']
                    
                    subnet_azs = []
                    for subnet_id in subnets:
                        response = ec2.describe_subnets(SubnetIds=[subnet_id])
                        az = response['Subnets'][0]['AvailabilityZone']
                        subnet_azs.append(az)
                    
                    if len(set(subnet_azs)) < 2:
                        raise Exception("Public subnets must be in at least 2 different AZs")
                
                cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
            except Exception as e:
                cfnresponse.send(event, context, cfnresponse.FAILED, {}, str(e))
```

## 🚀 Deployment Steps

### 1. Environment Setup
```bash
#!/bin/bash
# setup-deployment.sh

set -e

# Configuration
STACK_NAME="flashbang-honeypot"
REGION="us-east-1"
PROFILE="default"

# Get current IP automatically
MY_IP=$(curl -s https://checkip.amazonaws.com/)/32
echo "Detected IP: $MY_IP"

# Validate AWS credentials
echo "Validating AWS credentials..."
aws sts get-caller-identity --profile $PROFILE

# Check if stack already exists
if aws cloudformation describe-stacks --stack-name $STACK_NAME --profile $PROFILE 2>/dev/null; then
    echo "Stack $STACK_NAME already exists. Use update-stack instead."
    exit 1
fi

echo "Ready for deployment!"
```

### 2. Parameter File Creation
```bash
# Create parameters file
cat > parameters.json << EOF
[
  {
    "ParameterKey": "MyVPC",
    "ParameterValue": "vpc-xxxxxxxx"
  },
  {
    "ParameterKey": "PublicSubnets",
    "ParameterValue": "subnet-xxxxxxxx,subnet-yyyyyyyy"
  },
  {
    "ParameterKey": "PrivateSubnet",
    "ParameterValue": "subnet-zzzzzzzz"
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
  }
]
EOF
```

### 3. Deployment Command
```bash
# Deploy with comprehensive error handling
aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name $STACK_NAME \
  --parameter-overrides file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION \
  --profile $PROFILE \
  --no-fail-on-empty-changeset \
  --tags \
    Project=FlashBang \
    Environment=Production \
    Owner=$(aws sts get-caller-identity --query Arn --output text) \
  || {
    echo "Deployment failed. Checking stack events..."
    aws cloudformation describe-stack-events \
      --stack-name $STACK_NAME \
      --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].[LogicalResourceId,ResourceStatusReason]' \
      --output table
    exit 1
  }
```

## 🔧 Common Issues & Fixes

### 1. IAM Permission Issues
```bash
# Create minimal IAM policy for deployment
cat > flashbang-deploy-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "ec2:*",
        "s3:*",
        "lambda:*",
        "iam:*",
        "logs:*",
        "dynamodb:*",
        "elasticloadbalancing:*",
        "events:*",
        "sns:*",
        "wafv2:*",
        "certificatemanager:*",
        "ssm:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Attach to user/role
aws iam put-user-policy \
  --user-name your-username \
  --policy-name FlashBangDeployPolicy \
  --policy-document file://flashbang-deploy-policy.json
```

### 2. Resource Limit Issues
```bash
# Check and request limit increases
aws service-quotas list-service-quotas --service-code ec2 \
  --query 'Quotas[?QuotaName==`Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances`]'

# Request increase if needed
aws service-quotas request-service-quota-increase \
  --service-code ec2 \
  --quota-code L-1216C47A \
  --desired-value 20
```

### 3. Subnet Validation Issues
```bash
# Validate subnet configuration
validate_subnets() {
    local vpc_id=$1
    local public_subnets=$2
    local private_subnet=$3
    
    echo "Validating subnets for VPC: $vpc_id"
    
    # Check if subnets exist and are in the VPC
    IFS=',' read -ra SUBNET_ARRAY <<< "$public_subnets"
    for subnet in "${SUBNET_ARRAY[@]}"; do
        aws ec2 describe-subnets --subnet-ids $subnet \
          --query 'Subnets[0].[SubnetId,VpcId,AvailabilityZone,MapPublicIpOnLaunch]' \
          --output table
    done
    
    aws ec2 describe-subnets --subnet-ids $private_subnet \
      --query 'Subnets[0].[SubnetId,VpcId,AvailabilityZone,MapPublicIpOnLaunch]' \
      --output table
}
```

## 📊 Post-Deployment Validation

### 1. Stack Status Check
```bash
# Check stack status
aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].StackStatus' \
  --output text

# Get stack outputs
aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].Outputs' \
  --output table
```

### 2. Resource Health Check
```bash
#!/bin/bash
# health-check.sh

STACK_NAME="flashbang-honeypot"

echo "🔍 FlashBang Health Check"
echo "========================"

# Get instance ID
INSTANCE_ID=$(aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].Outputs[?OutputKey==`FlashBangInstanceId`].OutputValue' \
  --output text)

# Check instance status
echo "Instance Status:"
aws ec2 describe-instance-status --instance-ids $INSTANCE_ID \
  --query 'InstanceStatuses[0].[InstanceState.Name,SystemStatus.Status,InstanceStatus.Status]' \
  --output table

# Check ALB health
ALB_DNS=$(aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].Outputs[?OutputKey==`FlashBangURL`].OutputValue' \
  --output text | sed 's|http://||')

echo "ALB Health Check:"
curl -s -o /dev/null -w "%{http_code}" http://$ALB_DNS/health-check-fake-endpoint

# Check services via Session Manager
echo "Service Status (via Session Manager):"
aws ssm send-command \
  --instance-ids $INSTANCE_ID \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["systemctl status flashbang-flask flashbang-interactive flashbang-web nginx"]' \
  --query 'Command.CommandId' \
  --output text
```

### 3. Security Validation
```bash
# Check security group rules
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=*flashbang*" \
  --query 'SecurityGroups[*].[GroupName,IpPermissions[*].[IpProtocol,FromPort,ToPort,IpRanges[*].CidrIp]]' \
  --output table

# Verify S3 bucket security
aws s3api get-bucket-public-access-block \
  --bucket $(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --query 'Stacks[0].Outputs[?OutputKey==`FlashBangLogsBucket`].OutputValue' \
    --output text)
```

## 🔄 Update Procedures

### 1. Safe Update Process
```bash
# Create changeset first
aws cloudformation create-change-set \
  --stack-name $STACK_NAME \
  --template-body file://v2.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --change-set-name update-$(date +%Y%m%d-%H%M%S)

# Review changes
aws cloudformation describe-change-set \
  --stack-name $STACK_NAME \
  --change-set-name update-$(date +%Y%m%d-%H%M%S) \
  --query 'Changes[*].[Action,ResourceChange.LogicalResourceId,ResourceChange.ResourceType]' \
  --output table

# Execute if safe
aws cloudformation execute-change-set \
  --stack-name $STACK_NAME \
  --change-set-name update-$(date +%Y%m%d-%H%M%S)
```

### 2. Rollback Plan
```bash
# Monitor deployment
watch aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].StackStatus' \
  --output text

# Rollback if needed
aws cloudformation cancel-update-stack --stack-name $STACK_NAME
# or
aws cloudformation continue-update-rollback --stack-name $STACK_NAME
```

## 🧪 Testing Framework

### 1. Automated Testing
```bash
#!/bin/bash
# test-deployment.sh

test_honeypot_response() {
    local alb_url=$1
    echo "Testing honeypot responses..."
    
    # Test main page
    response=$(curl -s -o /dev/null -w "%{http_code}" $alb_url)
    if [ "$response" = "200" ]; then
        echo "✅ Main page accessible"
    else
        echo "❌ Main page failed: $response"
    fi
    
    # Test honeypot endpoints
    for endpoint in "/admin" "/.env" "/shell"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" $alb_url$endpoint)
        echo "Endpoint $endpoint: $response"
    done
}

test_logging() {
    echo "Testing logging functionality..."
    # Check CloudWatch logs
    aws logs describe-log-groups \
      --log-group-name-prefix "/aws/ec2/$STACK_NAME" \
      --query 'logGroups[*].logGroupName'
}

test_alerting() {
    echo "Testing alerting..."
    # Send test alert
    aws sns publish \
      --topic-arn $(aws cloudformation describe-stacks \
        --stack-name $STACK_NAME \
        --query 'Stacks[0].Outputs[?OutputKey==`FlashBangAlerts`].OutputValue' \
        --output text) \
      --message "FlashBang test alert"
}
```

## 📋 Troubleshooting Guide

### Common Error Messages

1. **"The specified VPC does not exist"**
   ```bash
   # Verify VPC ID
   aws ec2 describe-vpcs --vpc-ids vpc-xxxxxxxx
   ```

2. **"Subnet subnet-xxxxxxxx does not exist"**
   ```bash
   # Check subnet exists and is in correct VPC
   aws ec2 describe-subnets --subnet-ids subnet-xxxxxxxx
   ```

3. **"KeyPair 'key-name' does not exist"**
   ```bash
   # List available key pairs
   aws ec2 describe-key-pairs
   ```

4. **"CREATE_FAILED: FlashBangLogsBucket already exists"**
   ```bash
   # Use unique bucket name or delete existing bucket
   aws s3 rb s3://bucket-name --force
   ```

5. **"Lambda function failed to create"**
   ```bash
   # Check Lambda service limits
   aws lambda get-account-settings
   ```

### Debug Commands
```bash
# Get detailed stack events
aws cloudformation describe-stack-events \
  --stack-name $STACK_NAME \
  --query 'StackEvents[*].[Timestamp,LogicalResourceId,ResourceStatus,ResourceStatusReason]' \
  --output table

# Check resource drift
aws cloudformation detect-stack-drift --stack-name $STACK_NAME

# Get stack resources
aws cloudformation list-stack-resources --stack-name $STACK_NAME
```

## 🎯 Success Criteria

Your deployment is successful when:

- ✅ CloudFormation stack status is `CREATE_COMPLETE`
- ✅ EC2 instance is running and healthy
- ✅ ALB health checks are passing
- ✅ All honeypot services are running
- ✅ Logs are being generated and stored
- ✅ Alerts are configured and working
- ✅ Session Manager access is functional
- ✅ Security groups are properly configured

## 📞 Support Resources

- **AWS CloudFormation Documentation**: https://docs.aws.amazon.com/cloudformation/
- **AWS CLI Reference**: https://docs.aws.amazon.com/cli/
- **FlashBang GitHub Issues**: https://github.com/your-org/flashbang-honeypot/issues
- **AWS Support**: https://aws.amazon.com/support/

Remember: Always test in a non-production environment first! 