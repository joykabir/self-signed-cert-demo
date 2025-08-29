#!/bin/bash

# run-demo.sh - Self-Signed Certificate Demo Script
# This script demonstrates the SSL server with concurrent load testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
JAR_NAME="self-signed-cert-demo.jar"
SERVER_PORT=9001
SERVER_PID=""
KEYSTORE_FILE="ssl-demo.p12"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if server is running
check_server() {
    if curl -k -s --connect-timeout 5 https://localhost:${SERVER_PORT}/api/status > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        print_status "Stopping server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi

    # Kill any remaining Java processes for our demo
    pkill -f "self-signed-cert-demo" 2>/dev/null || true

    print_success "Cleanup completed"
}

# Function to start the server
start_server() {
    print_status "Starting HTTPS server on port ${SERVER_PORT}..."

    if [ ! -f "$JAR_NAME" ]; then
        print_error "JAR file not found: $JAR_NAME"
        print_status "Building the project..."
        mvn clean package -q

        if [ ! -f "target/$JAR_NAME" ]; then
            print_error "Failed to build JAR file"
            exit 1
        fi

        cp "target/$JAR_NAME" .
    fi

    # Start server in background
    java -jar "$JAR_NAME" --server --daemon --port "$SERVER_PORT" > server.log 2>&1 &
    SERVER_PID=$!

    print_status "Server started with PID: $SERVER_PID"
    print_status "Waiting for server to be ready..."

    # Wait for server to start (max 30 seconds)
    for i in {1..30}; do
        if check_server; then
            print_success "Server is ready!"
            return 0
        fi
        echo -n "."
        sleep 1
    done

    print_error "Server failed to start within 30 seconds"
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    cat server.log
    exit 1
}

# Function to run basic connectivity tests
test_connectivity() {
    print_status "Testing basic connectivity..."

    # Test 1: Status endpoint
    print_status "Testing /api/status endpoint..."
    if curl -k -s https://localhost:${SERVER_PORT}/api/status | jq . > /dev/null 2>&1; then
        print_success "✓ Status endpoint working"
    else
        print_warning "Status endpoint test failed"
    fi

    # Test 2: Certificate endpoint
    print_status "Testing /api/certificate endpoint..."
    if curl -k -s https://localhost:${SERVER_PORT}/api/certificate | jq . > /dev/null 2>&1; then
        print_success "✓ Certificate endpoint working"
    else
        print_warning "Certificate endpoint test failed"
    fi

    # Test 3: Stats endpoint
    print_status "Testing /api/stats endpoint..."
    if curl -k -s https://localhost:${SERVER_PORT}/api/stats | jq . > /dev/null 2>&1; then
        print_success "✓ Stats endpoint working"
    else
        print_warning "Stats endpoint test failed"
    fi
}

# Function to run concurrent load tests
run_load_test() {
    local num_requests=$1
    local concurrency=$2
    local endpoint=$3

    print_status "Running load test: $num_requests requests with concurrency $concurrency to $endpoint"

    # Create a temporary script for parallel requests
    cat > load_test.sh << EOF
#!/bin/bash
make_request() {
    local id=\$1
    local start_time=\$(date +%s%3N)
    local response=\$(curl -k -s -w "%{http_code}:%{time_total}" https://localhost:${SERVER_PORT}${endpoint} 2>/dev/null)
    local end_time=\$(date +%s%3N)
    local duration=\$((end_time - start_time))
    local http_code=\$(echo \$response | cut -d: -f1)
    local curl_time=\$(echo \$response | cut -d: -f2)

    if [ "\$http_code" = "200" ]; then
        echo "SUCCESS,\$id,\$duration,\$curl_time"
    else
        echo "ERROR,\$id,\$duration,\$http_code"
    fi
}

export -f make_request

seq 1 $num_requests | xargs -n 1 -P $concurrency -I {} bash -c 'make_request {}'
EOF

    chmod +x load_test.sh

    print_status "Executing load test..."
    local start_time=$(date +%s)

    # Run the load test and capture results
    ./load_test.sh > load_results.txt

    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))

    # Analyze results
    local total_requests=$(wc -l < load_results.txt)
    local successful_requests=$(grep -c "^SUCCESS" load_results.txt || echo 0)
    local failed_requests=$(grep -c "^ERROR" load_results.txt || echo 0)
    local success_rate=$(echo "scale=2; $successful_requests * 100 / $total_requests" | bc -l 2>/dev/null || echo "0")
    local throughput=$(echo "scale=2; $total_requests / $total_time" | bc -l 2>/dev/null || echo "0")

    # Calculate response time statistics
    local avg_response_time=$(grep "^SUCCESS" load_results.txt | cut -d, -f3 | awk '{sum+=$1; count++} END {if(count>0) print sum/count; else print 0}')
    local min_response_time=$(grep "^SUCCESS" load_results.txt | cut -d, -f3 | sort -n | head -1)
    local max_response_time=$(grep "^SUCCESS" load_results.txt | cut -d, -f3 | sort -n | tail -1)

    print_success "Load Test Results for $endpoint:"
    echo "  📊 Total Requests: $total_requests"
    echo "  ✅ Successful: $successful_requests"
    echo "  ❌ Failed: $failed_requests"
    echo "  📈 Success Rate: ${success_rate}%"
    echo "  ⚡ Throughput: ${throughput} requests/second"
    echo "  🕐 Total Time: ${total_time} seconds"
    echo "  ⏱️  Avg Response Time: ${avg_response_time} ms"
    echo "  🏃 Min Response Time: ${min_response_time} ms"
    echo "  🐌 Max Response Time: ${max_response_time} ms"
    echo

    # Cleanup
    rm -f load_test.sh load_results.txt
}

# Function to run stress tests
run_stress_tests() {
    print_status "Running stress tests..."

    # Test 1: Light load
    run_load_test 50 5 "/api/status"

    # Test 2: Medium load
    run_load_test 100 10 "/api/certificate"

    # Test 3: Heavy load
    run_load_test 200 20 "/api/status"

    # Test 4: Mixed endpoints
    print_status "Testing mixed endpoints concurrently..."

    # Start multiple load tests in parallel
    run_load_test 50 10 "/api/status" &
    local pid1=$!

    run_load_test 50 10 "/api/certificate" &
    local pid2=$!

    run_load_test 50 10 "/api/stats" &
    local pid3=$!

    # Wait for all tests to complete
    wait $pid1 $pid2 $pid3

    print_success "Mixed endpoint stress test completed"
}

# Function to demonstrate SSL features
demonstrate_ssl_features() {
    print_status "Demonstrating SSL features..."

    # Show certificate details
    print_status "Certificate Information:"
    if command -v openssl >/dev/null 2>&1; then
        echo | openssl s_client -connect localhost:${SERVER_PORT} -servername localhost 2>/dev/null | openssl x509 -text -noout | head -20
    else
        curl -k -s https://localhost:${SERVER_PORT}/api/certificate | jq '.certificate | {subject, keySize, signatureAlgorithm, subjectAlternativeNames}'
    fi

    echo

    # Show SSL session details
    print_status "SSL Session Information:"
    curl -k -s https://localhost:${SERVER_PORT}/api/status | jq '.sslSession'

    echo

    # Demonstrate certificate validation failure
    print_status "Demonstrating certificate validation (should fail):"
    if curl -s --connect-timeout 5 https://localhost:${SERVER_PORT}/api/status 2>&1 | grep -q "certificate verify failed"; then
        print_success "✓ Certificate validation correctly failed for self-signed certificate"
    else
        print_warning "Certificate validation test inconclusive"
    fi

    # Show successful connection with -k flag
    print_status "Demonstrating successful connection with certificate bypass:"
    if curl -k -s https://localhost:${SERVER_PORT}/api/status | jq -r '.status' | grep -q "OK"; then
        print_success "✓ Connection successful with certificate validation bypass"
    else
        print_warning "Bypass connection test failed"
    fi
}

# Function to run JUnit tests
run_junit_tests() {
    print_status "Running JUnit tests..."

    if mvn test -q; then
        print_success "All JUnit tests passed!"
    else
        print_warning "Some JUnit tests failed. Check the output above."
    fi
}

# Function to show real-time monitoring
show_real_time_monitoring() {
    print_status "Starting real-time monitoring (press Ctrl+C to stop)..."

    trap 'return' INT

    while true; do
        clear
        echo -e "${BLUE}=== Real-Time SSL Server Monitoring ===${NC}"
        echo "Server: https://localhost:${SERVER_PORT}"
        echo "Time: $(date)"
        echo

        # Get server stats
        local stats=$(curl -k -s https://localhost:${SERVER_PORT}/api/stats 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Server Status: ONLINE${NC}"
            echo "Total Requests: $(echo "$stats" | jq -r '.totalRequests // "N/A"')"
            echo "Server Uptime: $(echo "$stats" | jq -r '.serverUptime // "N/A"')"
        else
            echo -e "${RED}Server Status: OFFLINE${NC}"
        fi

        echo
        echo "Press Ctrl+C to stop monitoring..."
        sleep 2
    done
}

# Main menu function
show_menu() {
    echo
    echo -e "${BLUE}=== Self-Signed Certificate Demo Menu ===${NC}"
    echo "1. Start server and run basic tests"
    echo "2. Run connectivity tests"
    echo "3. Run load tests"
    echo "4. Run stress tests"
    echo "5. Demonstrate SSL features"
    echo "6. Run JUnit tests"
    echo "7. Real-time monitoring"
    echo "8. Interactive client mode"
    echo "9. Show configuration"
    echo "10. Exit"
    echo
    read -p "Choose an option (1-10): " choice

    case $choice in
        1)
            start_server
            test_connectivity
            ;;
        2)
            if ! check_server; then
                print_warning "Server not running. Starting server first..."
                start_server
            fi
            test_connectivity
            ;;
        3)
            if ! check_server; then
                print_warning "Server not running. Starting server first..."
                start_server
            fi
            run_load_test 100 10 "/api/status"
            ;;
        4)
            if ! check_server; then
                print_warning "Server not running. Starting server first..."
                start_server
            fi
            run_stress_tests
            ;;
        5)
            if ! check_server; then
                print_warning "Server not running. Starting server first..."
                start_server
            fi
            demonstrate_ssl_features
            ;;
        6)
            run_junit_tests
            ;;
        7)
            if ! check_server; then
                print_warning "Server not running. Starting server first..."
                start_server
            fi
            show_real_time_monitoring
            ;;
        8)
            if ! check_server; then
                print_warning "Server not running. Starting server first..."
                start_server
            fi
            java -jar "$JAR_NAME" --interactive --port "$SERVER_PORT"
            ;;
        9)
            java -jar "$JAR_NAME" --show-config
            ;;
        10)
            cleanup
            exit 0
            ;;
        *)
            print_error "Invalid option. Please choose 1-10."
            ;;
    esac
}

# Trap cleanup on exit
trap cleanup EXIT

# Check dependencies
print_status "Checking dependencies..."

if ! command -v java >/dev/null 2>&1; then
    print_error "Java not found. Please install JDK 24 or later."
    exit 1
fi

if ! command -v mvn >/dev/null 2>&1; then
    print_error "Maven not found. Please install Maven."
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    print_error "curl not found. Please install curl."
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    print_warning "jq not found. JSON output will not be formatted."
fi

if ! command -v bc >/dev/null 2>&1; then
    print_warning "bc not found. Some calculations may not work."
fi

print_success "Dependencies check completed"

# Check if arguments are provided
if [ $# -eq 0 ]; then
    # Interactive mode
    while true; do
        show_menu
        echo
        read -p "Press Enter to continue or 'q' to quit: " continue_choice
        if [ "$continue_choice" = "q" ]; then
            break
        fi
    done
else
    # Command line mode
    case $1 in
        "start")
            start_server
            test_connectivity
            print_status "Server is running. Use 'curl -k https://localhost:${SERVER_PORT}/api/status' to test."
            print_status "Press Ctrl+C to stop the server."
            wait
            ;;
        "test")
            start_server
            test_connectivity
            run_load_test 50 5 "/api/status"
            ;;
        "load")
            start_server
            run_stress_tests
            ;;
        "ssl")
            start_server
            demonstrate_ssl_features
            ;;
        "junit")
            run_junit_tests
            ;;
        "monitor")
            start_server
            show_real_time_monitoring
            ;;
        *)
            echo "Usage: $0 [start|test|load|ssl|junit|monitor]"
            echo "  start  - Start server and run basic tests"
            echo "  test   - Run connectivity and light load tests"
            echo "  load   - Run comprehensive load tests"
            echo "  ssl    - Demonstrate SSL features"
            echo "  junit  - Run JUnit tests"
            echo "  monitor - Real-time monitoring"
            echo "  (no args) - Interactive menu"
            exit 1
            ;;
    esac
fi

print_success "Demo completed successfully!"