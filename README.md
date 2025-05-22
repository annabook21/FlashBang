# FlashBang Honeypot System 🎯💥

A comprehensive, Looney Tunes-inspired honeypot framework designed to detect, confuse, and log unauthorized access attempts while maintaining complete legal and ethical compliance.

![FlashBang Logo](https://img.shields.io/badge/FlashBang-Honeypot-yellow?style=for-the-badge&logo=security&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-CloudFormation-orange?style=for-the-badge&logo=amazon-aws&logoColor=white)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation Guide](#installation-guide)
  - [AWS Deployment](#aws-deployment)
  - [Local Development](#local-development)
  - [Docker Deployment](#docker-deployment)
- [Module Documentation](#module-documentation)
  - [Core Honeypot](#core-honeypot)
  - [Interactive Services](#interactive-services)
  - [Web Application Honeypot](#web-application-honeypot)
  - [Deception Engine](#deception-engine)
- [Configuration](#configuration)
- [Monitoring & Alerts](#monitoring--alerts)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Overview

FlashBang is a non-lethal honeypot system that:
- 🎭 Lures attackers with fake vulnerabilities
- 📝 Logs all attack attempts comprehensively
- 🎪 Responds with humorous, confusing payloads
- 📊 Provides detailed analytics and threat intelligence
- 🚨 Sends real-time alerts for high-risk activities
- 🔒 Maintains complete legal and ethical compliance

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FlashBang Honeypot System                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │   AWS ALB   │  │  CloudFront  │  │   Route 53 DNS   │ │
│  └──────┬──────┘  └──────┬───────┘  └────────┬─────────┘ │
│         │                 │                    │           │
│  ┌──────▼─────────────────▼────────────────────▼────────┐ │
│  │              EC2 Instance (Honeypot)                  │ │
│  │  ┌─────────────────────────────────────────────────┐ │ │
│  │  │   Nginx (Reverse Proxy & Load Balancer)        │ │ │
│  │  └───────────────────┬─────────────────────────────┘ │ │
│  │                      │                                │ │
│  │  ┌─────────┬────────┴────────┬────────────────────┐ │ │
│  │  │Flask App│ SSH Honeypot    │ Container Services │ │ │
│  │  │ (Port   │ (Port 2222)     │ ┌───────────────┐ │ │ │
│  │  │  5000)  │                 │ │ FTP (21)      │ │ │ │
│  │  └─────────┘                 │ │ Telnet (23)   │ │ │ │
│  │                              │ │ MySQL (3306)  │ │ │ │
│  │                              │ │ Redis (6379)  │ │ │ │
│  │                              │ └───────────────┘ │ │ │
│  │                              └────────────────────┘ │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ CloudWatch   │  │ S3 Bucket    │  │ DynamoDB       │  │
│  │ Logs & Alarm │  │ (Log Archive)│  │ (Analytics)    │  │
│  └──────────────┘  └──────────────┘  └────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Lambda       │  │ SNS Topics   │  │ Threat Intel   │  │
│  │ (Processor)  │  │ (Alerts)     │  │ (AbuseIPDB)    │  │
│  └──────────────┘  └──────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### System Requirements
- Python 3.9 or higher
- AWS Account (for cloud deployment)
- Docker & Docker Compose (for container deployment)
- 2GB RAM minimum (4GB recommended)
- 20GB disk space
- Ubuntu 20.04+ or compatible Linux distribution

### Required Tools
```bash
# Install required system packages
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git nginx docker.io docker-compose awscli jq

# Install Python dependencies
pip3 install flask boto3 requests flask-limiter asyncio aiofiles
```

### AWS Requirements
- AWS CLI configured with appropriate credentials
- EC2 Key Pair for SSH access
- VPC with public and private subnets
- IAM permissions for CloudFormation, EC2, S3, Lambda, etc.

## Installation Guide

### AWS Deployment

1. **Clone the repository**
```bash
git clone https://github.com/your-org/flashbang-honeypot.git
cd flashbang-honeypot
```

2. **Configure AWS CLI**
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, Region, and Output format
```

3. **Deploy using CloudFormation**
```bash
# Set your parameters
STACK_NAME="flashbang-honeypot"
YOUR_IP="YOUR.PUBLIC.IP.ADDRESS/32"
VPC_ID="vpc-xxxxxxxx"
PUBLIC_SUBNETS="subnet-xxxxxxxx,subnet-yyyyyyyy"
PRIVATE_SUBNET="subnet-zzzzzzzz"
KEY_NAME="your-ec2-keypair"
EMAIL="your-email@example.com"
DOMAIN="honeypot.yourdomain.com"  # Optional

# Deploy the stack
aws cloudformation create-stack \
  --stack-name $STACK_NAME \
  --template-body file://flashbang-cloudformation.yaml \
  --parameters \
    ParameterKey=MyIP,ParameterValue=$YOUR_IP \
    ParameterKey=MyVPC,ParameterValue=$VPC_ID \
    ParameterKey=PublicSubnets,ParameterValue=\"$PUBLIC_SUBNETS\" \
    ParameterKey=PrivateSubnet,ParameterValue=$PRIVATE_SUBNET \
    ParameterKey=KeyName,ParameterValue=$KEY_NAME \
    ParameterKey=NotificationEmail,ParameterValue=$EMAIL \
    ParameterKey=DomainName,ParameterValue=$DOMAIN \
    ParameterKey=EnableS3LogBackup,ParameterValue=true \
    ParameterKey=EnableCloudWatchLogs,ParameterValue=true \
    ParameterKey=EnableHTTPS,ParameterValue=true \
  --capabilities CAPABILITY_NAMED_IAM

# Monitor deployment
aws cloudformation describe-stacks --stack-name $STACK_NAME --query 'Stacks[0].StackStatus'
```

4. **Get deployment outputs**
```bash
# Get honeypot URL
aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].Outputs[?OutputKey==`FlashBangURL`].OutputValue' \
  --output text

# Get SSH command
aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --query 'Stacks[0].Outputs[?OutputKey==`SSHCommand`].OutputValue' \
  --output text
```

### Local Development

1. **Set up Python environment**
```bash
cd flashbang-honeypot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Create requirements.txt**
```bash
cat > requirements.txt << EOF
flask==2.3.3
flask-limiter==3.3.1
boto3==1.28.40
requests==2.31.0
aiofiles==23.2.1
asyncio==3.4.3
asyncssh==2.13.2
pyftpdlib==1.5.7
redis==5.0.0
psutil==5.9.5
EOF
```

3. **Run the basic Flask honeypot**
```bash
# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=development
export AWS_REGION=us-east-1  # Optional

# Run the application
python app.py
```

4. **Run the interactive services honeypot**
```bash
# In a new terminal
python interactive_services.py
```

5. **Run the web application honeypot**
```bash
# In another terminal
python web_honeypot.py
```

### Docker Deployment

1. **Create Docker Compose file**
```yaml
# docker-compose.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - flask-app
      - ssh-honeypot
    networks:
      - honeypot-net

  flask-app:
    build:
      context: .
      dockerfile: Dockerfile.flask
    environment:
      - FLASK_ENV=production
      - AWS_REGION=${AWS_REGION}
      - SNS_TOPIC_ARN=${SNS_TOPIC_ARN}
      - ENABLE_THREAT_INTEL=${ENABLE_THREAT_INTEL}
    volumes:
      - ./logs:/opt/flashbang/logs
    networks:
      - honeypot-net

  ssh-honeypot:
    build:
      context: .
      dockerfile: Dockerfile.ssh
    ports:
      - "2222:2222"
    volumes:
      - ./logs:/logs
    networks:
      - honeypot-net

  ftp-honeypot:
    build:
      context: .
      dockerfile: Dockerfile.ftp
    ports:
      - "21:21"
    volumes:
      - ./logs:/logs
    networks:
      - honeypot-net

  telnet-honeypot:
    build:
      context: .
      dockerfile: Dockerfile.telnet
    ports:
      - "23:23"
    volumes:
      - ./logs:/logs
    networks:
      - honeypot-net

  log-processor:
    build:
      context: .
      dockerfile: Dockerfile.processor
    environment:
      - S3_BUCKET=${S3_BUCKET}
      - DYNAMODB_TABLE=${DYNAMODB_TABLE}
    volumes:
      - ./logs:/logs:ro
    networks:
      - honeypot-net

networks:
  honeypot-net:
    driver: bridge
```

2. **Create Dockerfiles**

```dockerfile
# Dockerfile.flask
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
COPY templates/ templates/
COPY static/ static/
EXPOSE 5000
CMD ["python", "app.py"]
```

```dockerfile
# Dockerfile.ssh
FROM python:3.9-slim
WORKDIR /app
COPY requirements-ssh.txt .
RUN pip install -r requirements-ssh.txt
COPY interactive_services.py .
EXPOSE 2222
CMD ["python", "interactive_services.py"]
```

3. **Deploy with Docker Compose**
```bash
# Create .env file
cat > .env << EOF
AWS_REGION=us-east-1
SNS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789:flashbang-alerts
S3_BUCKET=flashbang-logs-bucket
DYNAMODB_TABLE=flashbang-analytics
ENABLE_THREAT_INTEL=true
ABUSEIPDB_KEY=your-api-key
EOF

# Build and run
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Module Documentation

### Core Honeypot

The main Flask application (`app.py`) provides:
- Web-based honeypot endpoints
- Attack logging and detection
- CloudWatch metrics integration
- SNS alerting

**Key endpoints:**
- `/` - Home page with honeypot links
- `/admin` - Fake admin panel
- `/.env` - Fake environment file
- `/shell` - Fake shell access
- `/rickroll` - Rickroll redirect

**Usage:**
```python
from app import app, log_attack

# Log custom attack
log_attack('/custom-endpoint', '192.168.1.100', 'CustomBot/1.0', request.headers)
```

### Interactive Services

The interactive services module (`interactive_services.py`) provides:
- SSH honeypot with realistic shell
- Telnet honeypot
- FTP honeypot
- Session tracking and risk scoring

**Configuration:**
```python
config = {
    'ssh': {'enabled': True, 'port': 2222, 'host': '0.0.0.0'},
    'telnet': {'enabled': True, 'port': 23, 'host': '0.0.0.0'},
    'ftp': {'enabled': True, 'port': 21, 'host': '0.0.0.0'},
}

orchestrator = HoneypotOrchestrator(config)
await orchestrator.start_services()
```

### Web Application Honeypot

The web honeypot module (`web_honeypot.py`) provides:
- Realistic web application vulnerabilities
- SQL injection detection
- XSS detection
- Fake API endpoints
- Credential harvesting

**Attack Detection:**
```python
from web_honeypot import WebHoneypot

honeypot = WebHoneypot()
attack_type, risk_score = honeypot.detect_attack_patterns(user_input)
honeypot.log_attack(attack_type, risk_score, user_input)
```

### Deception Engine

The deception module provides:
- Fake filesystem generation
- Realistic process lists
- Dynamic response generation
- Threat intelligence integration

**Usage:**
```python
from deception_engine import DeceptionEngine

engine = DeceptionEngine()
response = engine.get_fake_shell_response("ls -la")
threat_intel = engine.get_comprehensive_threat_intel("192.168.1.100")
```

## Configuration

### Environment Variables

```bash
# Core settings
FLASK_ENV=production
FLASK_APP=app.py
SECRET_KEY=your-secret-key

# AWS settings
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# Honeypot settings
HONEYPOT_MODE=high  # low, medium, high
ENABLE_THREAT_INTEL=true
ABUSEIPDB_KEY=your-abuseipdb-key
VIRUSTOTAL_API_KEY=your-virustotal-key

# Alerting
SNS_TOPIC_ARN=arn:aws:sns:region:account:topic
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
NOTIFICATION_EMAIL=security@example.com

# Storage
S3_BUCKET=flashbang-logs
DYNAMODB_TABLE=flashbang-analytics
ENABLE_S3_BACKUP=true
ENABLE_CLOUDWATCH_LOGS=true
```

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/flashbang
server {
    listen 80 default_server;
    server_name _;
    
    # Real IP from load balancer
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    # Custom logging
    log_format honeypot '$remote_addr - $remote_user [$time_local] '
                       '"$request" $status $body_bytes_sent '
                       '"$http_referer" "$http_user_agent" '
                       '"$http_x_forwarded_for"';
    
    access_log /var/log/nginx/flashbang_access.log honeypot;
    error_log /var/log/nginx/flashbang_error.log;
    
    # Flask app
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Fake vulnerable endpoints
    location ~ \.(git|env|sql|bak|backup|db|config)$ {
        proxy_pass http://127.0.0.1:5000;
    }
}
```

## Monitoring & Alerts

### CloudWatch Dashboard

Create a custom dashboard to monitor:
- Attack attempts per minute/hour
- Top attacking IPs
- Most targeted endpoints
- Geographic distribution of attacks
- Risk score trends

```bash
# Create dashboard using AWS CLI
aws cloudwatch put-dashboard \
  --dashboard-name FlashBangDashboard \
  --dashboard-body file://cloudwatch-dashboard.json
```

### Alert Configuration

1. **Email Alerts (SNS)**
```bash
# Subscribe to SNS topic
aws sns subscribe \
  --topic-arn $SNS_TOPIC_ARN \
  --protocol email \
  --notification-endpoint your-email@example.com
```

2. **Slack Alerts**
```python
# Configure in environment
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

3. **CloudWatch Alarms**
```bash
# High attack volume alarm
aws cloudwatch put-metric-alarm \
  --alarm-name flashbang-high-attack-volume \
  --alarm-description "Alert on high attack volume" \
  --metric-name AttackAttempts \
  --namespace FlashBang/Honeypot \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions $SNS_TOPIC_ARN
```

### Log Analysis

1. **View recent attacks**
```bash
# SSH to instance
ssh -i your-key.pem ubuntu@honeypot-ip

# View Flask logs
tail -f /opt/flashbang/logs/attacks.log

# View Nginx access logs
tail -f /var/log/nginx/flashbang_access.log

# View interactive service logs
sqlite3 /opt/flashbang/flashbang_attacks.db "SELECT * FROM attack_sessions ORDER BY start_time DESC LIMIT 10;"
```

2. **Export logs to S3**
```bash
# Manual export
aws s3 cp /opt/flashbang/logs/ s3://your-bucket/logs/ --recursive

# Automated daily export (via cron)
0 2 * * * /opt/flashbang/scripts/backup_logs.sh
```

## Security Considerations

### Isolation

1. **Network Isolation**
- Deploy honeypot in isolated subnet
- Use security groups to restrict access
- Implement VPC flow logs

2. **System Hardening**
- Regular security updates
- Fail2ban for SSH protection
- UFW firewall rules
- Read-only root filesystem (where possible)

### Operational Security

1. **Access Control**
- Use separate SSH keys for honeypot
- Implement MFA for AWS access
- Rotate credentials regularly
- Monitor administrative access

2. **Data Protection**
- Encrypt logs at rest (S3 SSE)
- Use TLS for all communications
- Sanitize logged data (remove real passwords)
- Implement log retention policies

### Legal Compliance

1. **Terms of Service**
- Display warning banners
- Log only attack data, not legitimate traffic
- Comply with local data protection laws
- Document all monitoring activities

2. **Incident Response**
- Have clear escalation procedures
- Document all high-risk attacks
- Coordinate with security team
- Maintain chain of custody for evidence

## Troubleshooting

### Common Issues

1. **Service won't start**
```bash
# Check service status
systemctl status flashbang

# Check logs
journalctl -u flashbang -f

# Verify port availability
netstat -tlnp | grep -E '(80|443|22|2222)'
```

2. **No attacks logged**
```bash
# Test locally
curl http://localhost/admin
curl http://localhost/.env

# Check file permissions
ls -la /opt/flashbang/logs/

# Verify database
sqlite3 /opt/flashbang/flashbang_attacks.db ".tables"
```

3. **CloudWatch metrics missing**
```bash
# Check IAM role
aws sts get-caller-identity

# Test metric publishing
aws cloudwatch put-metric-data \
  --namespace Test \
  --metric-name TestMetric \
  --value 1
```

### Performance Tuning

1. **Nginx optimization**
```nginx
# Add to nginx.conf
worker_processes auto;
worker_connections 1024;
keepalive_timeout 65;
gzip on;
```

2. **Python optimization**
```python
# Use production WSGI server
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

3. **Database optimization**
```sql
-- Create indexes
CREATE INDEX idx_ip_address ON web_attacks(ip_address);
CREATE INDEX idx_timestamp ON web_attacks(timestamp);
CREATE INDEX idx_attack_type ON web_attacks(attack_type);
```

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 for Python code
- Add unit tests for new features
- Update documentation
- Test in isolated environment
- Never commit real credentials

### Testing

```bash
# Run unit tests
python -m pytest tests/

# Run integration tests
python -m pytest tests/integration/

# Run security scan
bandit -r . -f json -o bandit-report.json
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by traditional honeypot systems
- Built with security community best practices
- Special thanks to all contributors

---

**Remember**: FlashBang is designed for defensive purposes only. Always ensure you have proper authorization before deploying honeypots on any network.

🎯 **Happy Hunting!** 💥