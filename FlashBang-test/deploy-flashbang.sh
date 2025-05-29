#!/bin/bash
# FlashBang Honeypot Deployment Script
# This script validates prerequisites and deploys the FlashBang honeypot safely

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
STACK_NAME="flashbang-honeypot"
TEMPLATE_FILE="v2.yaml"
REGION="us-east-1"
PROFILE="default"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity --profile $PROFILE &> /dev/null; then
        log_error "AWS credentials not configured or invalid."
        exit 1
    fi
    
    # Check template file exists
    if [ ! -f "$TEMPLATE_FILE" ]; then
        log_error "Template file $TEMPLATE_FILE not found."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

validate_template() {
    log_info "Validating CloudFormation template..."
    
    if aws cloudformation validate-template --template-body file://$TEMPLATE_FILE --profile $PROFILE > /dev/null; then
        log_success "Template validation passed"
    else
        log_error "Template validation failed"
        exit 1
    fi
}

get_user_input() {
    log_info "Gathering deployment parameters..."
    
    # Get VPC ID
    echo "Available VPCs:"
    aws ec2 describe-vpcs --profile $PROFILE --query 'Vpcs[*].[VpcId,Tags[?Key==`Name`].Value|[0],CidrBlock]' --output table
    read -p "Enter VPC ID: " VPC_ID
    
    # Get public subnets
    echo "Available subnets in VPC $VPC_ID:"
    aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --profile $PROFILE \
        --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock,MapPublicIpOnLaunch,Tags[?Key==`Name`].Value|[0]]' --output table
    
    read -p "Enter public subnet IDs (comma-separated, minimum 2): " PUBLIC_SUBNETS
    read -p "Enter private subnet ID: " PRIVATE_SUBNET
    
    # Get key pair
    echo "Available key pairs:"
    aws ec2 describe-key-pairs --profile $PROFILE --query 'KeyPairs[*].KeyName' --output table
    read -p "Enter key pair name: " KEY_NAME
    
    # SSH configuration
    read -p "Enable direct SSH access? (y/n): " ENABLE_SSH
    if [ "$ENABLE_SSH" = "y" ]; then
        ENABLE_DIRECT_SSH="true"
        MY_IP=$(curl -s https://checkip.amazonaws.com/)/32
        log_info "Detected your IP: $MY_IP"
        read -p "Use detected IP or enter custom IP (CIDR format): " CUSTOM_IP
        if [ ! -z "$CUSTOM_IP" ]; then
            MY_IP="$CUSTOM_IP"
        fi
    else
        ENABLE_DIRECT_SSH="false"
        MY_IP=""
        log_info "SSH access disabled. Use AWS Systems Manager Session Manager for access."
    fi
    
    # Optional parameters
    read -p "Enter notification email (optional): " NOTIFICATION_EMAIL
    read -p "Enter Slack webhook URL (optional): " SLACK_WEBHOOK
    read -p "Enter domain name for HTTPS (optional): " DOMAIN_NAME
}

create_parameter_file() {
    log_info "Creating parameter file..."
    
    cat > parameters.json << EOF
[
  {
    "ParameterKey": "MyVPC",
    "ParameterValue": "$VPC_ID"
  },
  {
    "ParameterKey": "PublicSubnets",
    "ParameterValue": "$PUBLIC_SUBNETS"
  },
  {
    "ParameterKey": "PrivateSubnet",
    "ParameterValue": "$PRIVATE_SUBNET"
  },
  {
    "ParameterKey": "KeyName",
    "ParameterValue": "$KEY_NAME"
  },
  {
    "ParameterKey": "EnableDirectSSH",
    "ParameterValue": "$ENABLE_DIRECT_SSH"
  },
  {
    "ParameterKey": "MyIP",
    "ParameterValue": "$MY_IP"
  },
  {
    "ParameterKey": "NotificationEmail",
    "ParameterValue": "$NOTIFICATION_EMAIL"
  },
  {
    "ParameterKey": "SlackWebhookURL",
    "ParameterValue": "$SLACK_WEBHOOK"
  },
  {
    "ParameterKey": "DomainName",
    "ParameterValue": "$DOMAIN_NAME"
  }
]
EOF
    
    log_success "Parameter file created"
}

check_existing_stack() {
    if aws cloudformation describe-stacks --stack-name $STACK_NAME --profile $PROFILE &> /dev/null; then
        log_warning "Stack $STACK_NAME already exists."
        read -p "Do you want to update it? (y/n): " UPDATE_STACK
        if [ "$UPDATE_STACK" != "y" ]; then
            log_info "Deployment cancelled."
            exit 0
        fi
        return 1
    fi
    return 0
}

deploy_stack() {
    local is_new_stack=$1
    
    if [ $is_new_stack -eq 0 ]; then
        log_info "Deploying new FlashBang stack..."
        OPERATION="deploy"
    else
        log_info "Updating existing FlashBang stack..."
        OPERATION="deploy"
    fi
    
    aws cloudformation $OPERATION \
        --template-file $TEMPLATE_FILE \
        --stack-name $STACK_NAME \
        --parameter-overrides file://parameters.json \
        --capabilities CAPABILITY_NAMED_IAM \
        --region $REGION \
        --profile $PROFILE \
        --no-fail-on-empty-changeset \
        --tags \
            Project=FlashBang \
            Environment=Production \
            DeployedBy=$(aws sts get-caller-identity --query Arn --output text --profile $PROFILE) \
            DeployedAt=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
    || {
        log_error "Deployment failed. Checking stack events..."
        aws cloudformation describe-stack-events \
            --stack-name $STACK_NAME \
            --profile $PROFILE \
            --query 'StackEvents[?ResourceStatus==`CREATE_FAILED` || ResourceStatus==`UPDATE_FAILED`].[LogicalResourceId,ResourceStatusReason]' \
            --output table
        exit 1
    }
}

wait_for_completion() {
    log_info "Waiting for stack deployment to complete..."
    
    aws cloudformation wait stack-create-complete \
        --stack-name $STACK_NAME \
        --profile $PROFILE \
        --region $REGION \
    || aws cloudformation wait stack-update-complete \
        --stack-name $STACK_NAME \
        --profile $PROFILE \
        --region $REGION \
    || {
        log_error "Stack deployment failed or timed out"
        exit 1
    }
}

display_outputs() {
    log_info "Deployment completed! Here are the stack outputs:"
    
    aws cloudformation describe-stacks \
        --stack-name $STACK_NAME \
        --profile $PROFILE \
        --query 'Stacks[0].Outputs' \
        --output table
    
    # Get specific important outputs
    INSTANCE_ID=$(aws cloudformation describe-stacks \
        --stack-name $STACK_NAME \
        --profile $PROFILE \
        --query 'Stacks[0].Outputs[?OutputKey==`FlashBangInstanceId`].OutputValue' \
        --output text)
    
    ALB_URL=$(aws cloudformation describe-stacks \
        --stack-name $STACK_NAME \
        --profile $PROFILE \
        --query 'Stacks[0].Outputs[?OutputKey==`FlashBangURL`].OutputValue' \
        --output text)
    
    SESSION_MANAGER_CMD=$(aws cloudformation describe-stacks \
        --stack-name $STACK_NAME \
        --profile $PROFILE \
        --query 'Stacks[0].Outputs[?OutputKey==`FlashBangSessionManagerCommand`].OutputValue' \
        --output text)
    
    echo ""
    log_success "🎯 FlashBang Honeypot Deployed Successfully!"
    echo ""
    echo "📋 Quick Access Information:"
    echo "  • Instance ID: $INSTANCE_ID"
    echo "  • Honeypot URL: $ALB_URL"
    echo "  • Session Manager: $SESSION_MANAGER_CMD"
    echo ""
    echo "🔧 Next Steps:"
    echo "  1. Test the honeypot: curl $ALB_URL"
    echo "  2. Access instance: $SESSION_MANAGER_CMD"
    echo "  3. Monitor logs: aws logs tail /aws/ec2/$STACK_NAME/flashbang --follow"
    echo "  4. Check health: curl $ALB_URL/health-check-fake-endpoint"
    echo ""
}

run_health_check() {
    log_info "Running post-deployment health check..."
    
    # Wait a bit for services to start
    sleep 30
    
    # Check ALB health
    if curl -s -o /dev/null -w "%{http_code}" $ALB_URL | grep -q "200"; then
        log_success "ALB health check passed"
    else
        log_warning "ALB health check failed - services may still be starting"
    fi
    
    # Check instance status
    INSTANCE_STATUS=$(aws ec2 describe-instance-status \
        --instance-ids $INSTANCE_ID \
        --profile $PROFILE \
        --query 'InstanceStatuses[0].InstanceStatus.Status' \
        --output text 2>/dev/null || echo "pending")
    
    if [ "$INSTANCE_STATUS" = "ok" ]; then
        log_success "Instance health check passed"
    else
        log_warning "Instance status: $INSTANCE_STATUS (may still be initializing)"
    fi
}

cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f parameters.json
}

# Main execution
main() {
    echo "🎯 FlashBang Honeypot Deployment Script"
    echo "======================================="
    echo ""
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    check_prerequisites
    validate_template
    get_user_input
    create_parameter_file
    
    if check_existing_stack; then
        IS_NEW_STACK=0
    else
        IS_NEW_STACK=1
    fi
    
    echo ""
    log_info "Deployment Summary:"
    echo "  • Stack Name: $STACK_NAME"
    echo "  • Region: $REGION"
    echo "  • VPC: $VPC_ID"
    echo "  • Public Subnets: $PUBLIC_SUBNETS"
    echo "  • Private Subnet: $PRIVATE_SUBNET"
    echo "  • Key Pair: $KEY_NAME"
    echo "  • Direct SSH: $ENABLE_DIRECT_SSH"
    if [ "$ENABLE_DIRECT_SSH" = "true" ]; then
        echo "  • SSH IP: $MY_IP"
    fi
    echo ""
    
    read -p "Proceed with deployment? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ]; then
        log_info "Deployment cancelled."
        exit 0
    fi
    
    deploy_stack $IS_NEW_STACK
    wait_for_completion
    display_outputs
    run_health_check
    
    echo ""
    log_success "🎉 FlashBang honeypot is ready to catch attackers!"
    echo ""
    echo "📚 Documentation:"
    echo "  • Deployment Guide: DEPLOYMENT_CHECKLIST.md"
    echo "  • Dynamic IP Solutions: DYNAMIC_IP_SOLUTIONS.md"
    echo "  • Project README: README.md"
    echo ""
    echo "⚠️  Security Reminder:"
    echo "  • Monitor the honeypot regularly"
    echo "  • Review captured attack data"
    echo "  • Keep the system updated"
    echo "  • Follow your organization's security policies"
}

# Run main function
main "$@" 