# FlashBang Dynamic IP Solutions

The FlashBang honeypot CloudFormation template has been updated to handle dynamic IP addresses. Here are the available solutions:

## Solution 1: AWS Systems Manager Session Manager (Recommended) ⭐

**This is the most secure and flexible approach** - no IP restrictions needed!

### How it works:
- Uses AWS Systems Manager Session Manager for secure shell access
- No need to open SSH port 22 to the internet
- Works from anywhere without IP restrictions
- All session activity is logged in CloudWatch

### Setup:
1. Deploy the stack with `EnableDirectSSH=false` (default)
2. Leave `MyIP` parameter empty
3. Access the instance using:
   ```bash
   aws ssm start-session --target i-1234567890abcdef0 --region us-east-1
   ```

### Benefits:
- ✅ No IP restrictions
- ✅ Enhanced security (no SSH port exposure)
- ✅ Session logging and auditing
- ✅ Works with dynamic IPs
- ✅ IAM-based access control
- ✅ No VPN required

### Requirements:
- AWS CLI v2 with Session Manager plugin
- Appropriate IAM permissions for SSM

## Solution 2: Dynamic IP Detection with Lambda

For users who prefer traditional SSH but have dynamic IPs:

### Option A: Automatic IP Detection
```yaml
# Add this Lambda function to automatically detect and update your IP
AutoUpdateMyIPLambda:
  Type: AWS::Lambda::Function
  Properties:
    Runtime: python3.12
    Handler: index.lambda_handler
    Code:
      ZipFile: |
        import boto3
        import requests
        import json
        
        def lambda_handler(event, context):
            # Get current public IP
            response = requests.get('https://checkip.amazonaws.com/')
            current_ip = response.text.strip() + '/32'
            
            # Update security group
            ec2 = boto3.client('ec2')
            sg_id = event['SecurityGroupId']
            
            # Remove old rule and add new one
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': event['OldIP']}]
                    }]
                )
            except:
                pass
                
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': current_ip, 'Description': 'Auto-updated IP'}]
                }]
            )
            
            return {'statusCode': 200, 'body': f'Updated to {current_ip}'}
```

### Option B: Scheduled IP Update
Set up a CloudWatch Events rule to run the Lambda every hour to check for IP changes.

## Solution 3: VPN or Bastion Host

### Option A: AWS Client VPN
```yaml
# Add Client VPN endpoint for secure access
ClientVPNEndpoint:
  Type: AWS::EC2::ClientVpnEndpoint
  Properties:
    AuthenticationOptions:
      - Type: certificate-authentication
        MutualAuthentication:
          ClientRootCertificateChainArn: !Ref ClientCertificateArn
    ClientCidrBlock: 10.0.0.0/16
    ConnectionLogOptions:
      Enabled: true
      CloudwatchLogGroup: !Ref VPNLogGroup
    ServerCertificateArn: !Ref ServerCertificateArn
```

### Option B: Bastion Host
Deploy a separate bastion host in a public subnet with Session Manager access.

## Solution 4: Multiple IP Ranges

For organizations with known IP ranges:

```yaml
Parameters:
  AllowedIPRanges:
    Type: CommaDelimitedList
    Description: List of CIDR blocks allowed SSH access
    Default: "203.0.113.0/24,198.51.100.0/24"

# In Security Group:
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: !Select [0, !Ref AllowedIPRanges]
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: !Select [1, !Ref AllowedIPRanges]
```

## Solution 5: API Gateway + Lambda Proxy

Create an API endpoint that updates your IP automatically:

```python
# Lambda function behind API Gateway
import boto3
import json

def lambda_handler(event, context):
    source_ip = event['requestContext']['identity']['sourceIp']
    
    # Update security group with new IP
    ec2 = boto3.client('ec2')
    # ... update logic here
    
    return {
        'statusCode': 200,
        'body': json.dumps(f'SSH access granted to {source_ip}')
    }
```

## Deployment Examples

### Example 1: Session Manager Only (Recommended)
```bash
aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name flashbang-honeypot \
  --parameter-overrides \
    MyVPC=vpc-12345678 \
    PublicSubnets=subnet-12345678,subnet-87654321 \
    PrivateSubnet=subnet-abcdef12 \
    KeyName=my-key-pair \
    EnableDirectSSH=false \
  --capabilities CAPABILITY_NAMED_IAM
```

### Example 2: Direct SSH with Current IP
```bash
# Get your current IP
MY_IP=$(curl -s https://checkip.amazonaws.com/)/32

aws cloudformation deploy \
  --template-file v2.yaml \
  --stack-name flashbang-honeypot \
  --parameter-overrides \
    MyVPC=vpc-12345678 \
    PublicSubnets=subnet-12345678,subnet-87654321 \
    PrivateSubnet=subnet-abcdef12 \
    KeyName=my-key-pair \
    EnableDirectSSH=true \
    MyIP=$MY_IP \
  --capabilities CAPABILITY_NAMED_IAM
```

### Example 3: Update Existing Stack with New IP
```bash
# Update just the IP parameter
NEW_IP=$(curl -s https://checkip.amazonaws.com/)/32

aws cloudformation update-stack \
  --stack-name flashbang-honeypot \
  --use-previous-template \
  --parameters \
    ParameterKey=MyIP,ParameterValue=$NEW_IP \
    ParameterKey=EnableDirectSSH,ParameterValue=true \
  --capabilities CAPABILITY_NAMED_IAM
```

## Access Methods Comparison

| Method | Security | Convenience | Dynamic IP Support | Setup Complexity |
|--------|----------|-------------|-------------------|------------------|
| Session Manager | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| Direct SSH | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐⭐ |
| Auto-Update Lambda | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| Client VPN | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐ |
| Bastion Host | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |

## Troubleshooting

### Session Manager Issues
```bash
# Install Session Manager plugin
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac/sessionmanager-bundle.zip" -o "sessionmanager-bundle.zip"
unzip sessionmanager-bundle.zip
sudo ./sessionmanager-bundle/install -i /usr/local/sessionmanagerplugin -b /usr/local/bin/session-manager-plugin

# Test connection
aws ssm describe-instance-information --region us-east-1
```

### IP Update Script
```bash
#!/bin/bash
# update-ip.sh - Script to update CloudFormation stack with new IP

STACK_NAME="flashbang-honeypot"
NEW_IP=$(curl -s https://checkip.amazonaws.com/)/32

echo "Updating stack with new IP: $NEW_IP"

aws cloudformation update-stack \
  --stack-name $STACK_NAME \
  --use-previous-template \
  --parameters \
    ParameterKey=MyIP,ParameterValue=$NEW_IP \
    ParameterKey=EnableDirectSSH,ParameterValue=true \
  --capabilities CAPABILITY_NAMED_IAM

echo "Stack update initiated. Check AWS Console for progress."
```

## Security Best Practices

1. **Use Session Manager when possible** - it's the most secure option
2. **Enable CloudTrail** to log all API calls and access attempts
3. **Use IAM roles** instead of access keys where possible
4. **Regularly rotate SSH keys** if using direct SSH access
5. **Monitor access logs** in CloudWatch
6. **Set up alerts** for unusual access patterns

## Cost Considerations

- **Session Manager**: ~$0.05 per session hour
- **Client VPN**: ~$0.10 per connection hour + $0.05 per GB
- **Lambda auto-update**: ~$0.20 per million requests
- **Direct SSH**: No additional AWS costs

**Recommendation**: Start with Session Manager for the best balance of security, convenience, and cost. 