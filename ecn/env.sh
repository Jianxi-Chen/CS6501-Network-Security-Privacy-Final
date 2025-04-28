#!/usr/bin/env bash
set -e

# 1. Switch to the Prague congestion control algorithm
sudo sysctl -w net.ipv4.tcp_congestion_control=prague

# 2. Verify the currently active congestion control algorithm
sysctl net.ipv4.tcp_congestion_control

# 3. Load the Prague TCP module and the dualPI2 queuing discipline
sudo modprobe tcp_prague
sudo modprobe sch_dualpi2

# 4. Attach dualPI2 qdisc to eth0
sudo tc qdisc add dev eth0 root dualpi2

# 5. Show the qdisc configuration on eth0
sudo tc qdisc show dev eth0
