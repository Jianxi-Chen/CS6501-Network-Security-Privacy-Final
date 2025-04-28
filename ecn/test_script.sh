#!/bin/bash

# Default values
cc="prague"
DURATION=240
PARALLEL_STREAMS=1
SERVER_IP="10.0.2.2"

# Parse command-line flags
while getopts c:d:p:s: flag
do
    case "${flag}" in
        c) cc=${OPTARG};;                    # Congestion control algorithm
        d) DURATION=${OPTARG};;              # Test duration
        p) PARALLEL_STREAMS=${OPTARG};;      # Parallel streams
        s) SERVER_IP=${OPTARG};;             # Server IP
    esac
done

# Set congestion control algorithm by writing to /proc
# sudo sh -c "echo $cc > /proc/sys/net/ipv4/tcp_congestion_control"

# Set output file based on congestion control algorithm
OUTPUT_FILE="${cc}_test.json"

# Display settings
echo "Running iperf3 test with:"
echo "Congestion control: $cc"
echo "Test duration: $DURATION seconds"
echo "Parallel streams: $PARALLEL_STREAMS"
echo "Server IP: $SERVER_IP"
echo "Output file: results/$OUTPUT_FILE"

# Ensure results directory exists
mkdir -p results

# Run iperf3 test and save results to a JSON file
iperf3 -c $SERVER_IP -t $DURATION -P $PARALLEL_STREAMS -J > "results/$OUTPUT_FILE"

# Confirm test completion
echo "Test completed. Results saved to results/$OUTPUT_FILE"