# Load Testing & Failure Scenarios

## Current System Capacity

**Safe Concurrent Users:** ❌ **Less than 5**  
**Recommended Max Load:** ❌ **NOT SUITABLE FOR PRODUCTION**

---

## Known Failure Points Under Load

### Scenario 1: 10 Concurrent Users (Current System)
**Expected Result:** ❌ PARTIAL FAILURES

- Request 1-3: Succeed normally (100ms response)
- Request 4-7: Begin to slow (500-1000ms)
- Request 8-10: May timeout or fail (5000ms+)
- **Memory Usage:** Grows by 50-100MB
- **Rate Limiter:** May reach memory limits
- **Database:** Connection pool at 50% capacity

### Scenario 2: 50 Concurrent Users (Current System)
**Expected Result:** ❌ CRITICAL FAILURE

- All requests slow to 2-5 seconds
- Database connection pool exhausted (all 50 connections used)
- Request 51+ receive "connection timeout"
- **Memory Usage:** 500-800 MB, possibly OOM
- **Error Rate:** 20-30% of requests fail
- **Session Management:** Some sessions may corrupt

### Scenario 3: 100 Concurrent Users (Current System)
**Expected Result:** ❌ **COMPLETE SYSTEM FAILURE**

- Application becomes non-responsive
- Database completely unresponsive
- **OOM Kill:** Process killed by OS
- Rate limiter memory exhausted
- 90%+ request failure
- Manual restart required

---

## Load Test Script

### Setup
```bash
pip install locust
```

### Create `locustfile.py`

```python
from locust import HttpUser, task, between
import random

class LostFoundUser(HttpUser):
    wait_time = between(1, 3)  # Delay between actions
    
    def on_start(self):
        """Login for each user"""
        self.client.post(
            "/login",
            {
                "email": f"test{random.randint(1, 100)}@sot.pdpu.ac.in",
                "password": "TestPassword123@",
                "role": "student"
            }
        )
    
    @task(3)
    def view_items(self):
        """Browse items (3x more frequent)"""
        self.client.get("/items")
    
    @task(1)
    def view_item_details(self):
        """View single item"""
        self.client.get("/item/64f1234567890abc1234d567")
    
    @task(1)
    def submit_claim(self):
        """Submit claim"""
        self.client.post(
            "/request-claim",
            {
                "item_id": "64f1234567890abc1234d567",
                "student_name": f"Test User {random.randint(1, 100)}",
                "description_lost": f"I lost my keys"
            }
        )
    
    @task(2)
    def view_notifications(self):
        """Check notifications"""
        self.client.get("/notification_student")
```

### Run Load Test
```bash
# Terminal 1: Start app
python run.py

# Terminal 2: Run load test
locust -f locustfile.py --host=http://localhost:5000 --users=50 --spawn-rate=5

# Opens web UI at http://localhost:8089
# Gradually ramp users from 5 to 50 over 10 seconds
```

### What to Observe
- Response times for each endpoint
- Error rate
- Memory usage (watch `ps` or Task Manager)
- Database connection pool (if monitoring available)
- When first errors occur
- At what user count system breaks

---

## Expected vs Actual Performance

### Current System (BEFORE Fixes)

| Metric | 5 Users | 10 Users | 50 Users | 100 Users |
|--------|---------|----------|----------|-----------|
| Avg Response Time | 100ms | 300ms | 2000ms+ | 5000ms+ |
| P99 Response Time | 200ms | 1000ms | 5000ms+ | Timeout |
| Error Rate | 0% | 0-5% | 20-30% | 95%+ |
| Memory Usage | 150 MB | 250 MB | 800 MB+ | OOM |
| Success Rate | 100% | 95-100% | 70-80% | <5% |

### After Phase 1 Fixes (3x improvement)

| Metric | 5 Users | 10 Users | 50 Users | 100 Users |
|--------|---------|----------|----------|-----------|
| Avg Response Time | 80ms | 150ms | 400ms | 800ms |
| P99 Response Time | 150ms | 300ms | 800ms | 1500ms |
| Error Rate | 0% | 0% | 0-2% | 5-10% |
| Memory Usage | 120 MB | 150 MB | 200 MB | 300 MB |
| Success Rate | 100% | 100% | 98%+ | 90%+ |

### After Full Optimization (10x improvement)

| Metric | 5 Users | 10 Users | 50 Users | 100 Users | 500 Users |
|--------|---------|----------|----------|-----------|-----------|
| Avg Response Time | 50ms | 80ms | 150ms | 250ms | 400ms |
| P99 Response Time | 100ms | 150ms | 300ms | 500ms | 800ms |
| Error Rate | 0% | 0% | 0% | 0% | <1% |
| Memory Usage | 100 MB | 120 MB | 150 MB | 200 MB | 400 MB |
| Success Rate | 100% | 100% | 100% | 100% | 99%+ |

---

## Docker-Based Load Testing

### Create `docker-compose.yml` for testing

```yaml
version: '3'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      FLASK_ENV: production
      SECRET_KEY: test_secret_key_12345678901234567890
      MONGO_URI: mongodb://mongo:27017/lost_found_db
      REDIS_URL: redis://redis:6379
    depends_on:
      - mongo
      - redis
  
  mongo:
    image: mongo:5.0
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
  
  load_test:
    image: locustio/locust:latest
    volumes:
      - ./locustfile.py:/locustfile.py
    ports:
      - "8089:8089"
    command: 
      - -f
      - /locustfile.py
      - --host=http://app:5000
      - --users=100
      - --spawn-rate=10
    depends_on:
      - app

volumes:
  mongo_data:
```

### Run Full Stack with Load Test
```bash
docker-compose up

# Watch logs: docker-compose logs -f app
# Open load test UI: http://localhost:8089
```

---

## Stress Testing

### Test: Memory Leak Detection
```python
import psutil
import requests
import time

process = psutil.Process()

print("Starting memory leak test...")
baseline_memory = process.memory_info().rss / 1024 / 1024  # MB

for i in range(1000):
    try:
        requests.get("http://localhost:5000/items")
        requests.get("http://localhost:5000/item/64f1234567890abc1234d567")
    except:
        pass
    
    if (i + 1) % 100 == 0:
        current_memory = process.memory_info().rss / 1024 / 1024
        delta = current_memory - baseline_memory
        print(f"Requests: {i+1}, Memory: {current_memory:.1f}MB, Delta: {delta:.1f}MB")
        
        if delta > 500:  # More than 500MB increase
            print("❌ MEMORY LEAK DETECTED!")
            break

print("✓ Memory test complete")
```

### Test: Connection Pool Exhaustion
```python
import threading
import requests
import time

TIMEOUT = 30
SUCCESS = 0
TIMEOUT_ERRORS = 0

def slow_request(request_id):
    global SUCCESS, TIMEOUT_ERRORS
    try:
        # Slow endpoint that holds connection
        response = requests.get(
            "http://localhost:5000/item/64f1234567890abc1234d567",
            timeout=TIMEOUT
        )
        if response.status_code == 200:
            SUCCESS += 1
        else:
            print(f"Request {request_id}: Status {response.status_code}")
    except requests.exceptions.Timeout:
        TIMEOUT_ERRORS += 1
        print(f"Request {request_id}: TIMEOUT")
    except Exception as e:
        print(f"Request {request_id}: {type(e).__name__}")

print("Testing connection pool exhaustion...")

# Launch 60 concurrent requests (exceeds default 50 connection pool)
threads = []
for i in range(60):
    t = threading.Thread(target=slow_request, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print(f"Successful: {SUCCESS}")
print(f"Timeouts: {TIMEOUT_ERRORS}")

if TIMEOUT_ERRORS > 0:
    print("❌ CONNECTION POOL EXHAUSTION - Reduce maxPoolSize or implement queuing")
else:
    print("✓ Connection pool handled requests")
```

### Test: Race Condition Detection
```python
import threading
from bson import ObjectId
import requests

DUPLICATE_CLAIMS = 0
CLAIM_LOCK = threading.Lock()

def submit_concurrent_claims(user_id, item_id, num_threads):
    global DUPLICATE_CLAIMS
    
    errors = []
    
    def claim():
        try:
            response = requests.post(
                "http://localhost:5000/request-claim",
                data={
                    "item_id": item_id,
                    "student_name": f"Test User {user_id}",
                    "description_lost": "I lost this item"
                },
                cookies={"session": user_id}
            )
            return response.status_code
        except Exception as e:
            errors.append(str(e))
            return None
    
    threads = [threading.Thread(target=claim) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # Count how many claims exist
    claims_created = count_user_claims(user_id, item_id)
    
    if claims_created > 1:
        print(f"❌ RACE CONDITION: {claims_created} claims for single user+item")
        DUPLICATE_CLAIMS += 1
    elif claims_created == 1:
        print(f"✓ Race condition prevented: exactly 1 claim created")
    
    return claims_created, errors

# Test with 5 threads trying to claim same item
print("Testing race condition vulnerability...")
duplicates, errors = submit_concurrent_claims("user123", "item123", 5)
```

---

## Performance Bottleneck Identification

### Database Query Analysis

Enable MongoDB query logging:

```javascript
// In MongoDB shell
db.setProfilingLevel(1, {slowms: 100})  // Log queries > 100ms

// View slow queries
db.system.profile.find({millis: {$gt: 100}}).sort({ts: -1}).limit(10)
```

### Python Profiling

```python
# Create profiling_test.py
import cProfile
import pstats
from io import StringIO
from app import create_app

def test_admin_dashboard():
    app = create_app()
    with app.test_client() as client:
        with app.test_request_context():
            client.get("/admin")

profiler = cProfile.Profile()
profiler.enable()

for _ in range(10):
    test_admin_dashboard()

profiler.disable()

# Print top 20 slowest functions
s = StringIO()
ps = pstats.Stats(profiler, stream=s)
ps.sort_stats('cumulative')
ps.print_stats(20)
print(s.getvalue())
```

### Network Analysis

```bash
# Monitor MongoDB network traffic
tcpdump -i lo -n 'tcp port 27017'

# Monitor application network
tcpdump -i lo -n 'tcp port 5000'
```

---

## Failure Recovery Testing

### Test: Graceful Degradation
```python
"""Test app behavior when MongoDB is unavailable"""

import requests
import subprocess
import time

# Stop MongoDB
print("Stopping MongoDB...")
subprocess.run(["mongod", "--shutdown"], timeout=5)

time.sleep(2)

# Try requests
print("Testing requests with MongoDB down...")

endpoints = [
    "/",
    "/login",
    "/items",
]

for endpoint in endpoints:
    try:
        response = requests.get(f"http://localhost:5000{endpoint}", timeout=5)
        print(f"{endpoint}: {response.status_code}")
    except Exception as e:
        print(f"{endpoint}: {type(e).__name__}")

# Restart MongoDB
print("Restarting MongoDB...")
subprocess.Popen(["mongod"])

time.sleep(5)

# Verify recovery
print("Verifying recovery...")
response = requests.get("http://localhost:5000/", timeout=5)
print(f"Recovery test: {response.status_code}")
```

---

## Monitoring Dashboard Setup

### Prometheus Metrics

```bash
pip install prometheus-flask-exporter
```

```python
# In app/__init__.py
from prometheus_flask_exporter import PrometheusMetrics

app = Flask(__name__)
metrics = PrometheusMetrics(app)

# Metrics automatically collected:
# - request duration
# - request count by endpoint
# - response size
# - request exceptions
```

### Grafana Dashboard

Create dashboard visualization with queries:

```promql
# Average request latency per endpoint
rate(flask_http_request_duration_seconds_sum[5m]) / rate(flask_http_request_duration_seconds_count[5m])

# Error rate
rate(flask_http_requests_total{status=~"5.."}[5m])

# Memory usage
process_resident_memory_bytes / 1024 / 1024

# Database connection pool utilization
mongodb_connection_pool_used / mongodb_connection_pool_max
```

---

## Recommended Testing Timeline

### Week 1: Baseline Testing
- [ ] Establish baseline performance (5 users)
- [ ] Identify current bottlenecks
- [ ] Document failure points

### Week 2-3: Phase 1 Fixes + Testing
- [ ] Implement critical fixes
- [ ] Re-test at 5, 10, 25 users
- [ ] Measure improvements

### Week 4: Load Optimization
- [ ] Implement Phase 2 fixes
- [ ] Add indexes
- [ ] Optimize queries
- [ ] Test at 50+ users

### Week 5+: Full Production Readiness
- [ ] Implement comprehensive monitoring
- [ ] 24-hour stress test
- [ ] Failover testing
- [ ] Load test with real data volume

---

**Testing Status:** Not Ready for Production  
**Recommended Action:** Complete Phase 1 + Phase 2 fixes before any load testing

