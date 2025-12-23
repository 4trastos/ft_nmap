#!/bin/bash
# test_ft_nmap.sh
# Script de test completo para ft_nmap

FT_NMAP="./ft_nmap"

TEST_HOSTS=("127.0.0.1" "google.es" "scanme.nmap.org")
PORT_RANGES=("33,55,80,443,450-500" "1-10" "80")
SCAN_TYPES=("SYN" "ACK" "FIN" "NULL" "XMAS" "UDP" "SYN,ACK,FIN,XMAS")
SPEEDUPS=(0 4 16 70 250)

LOGFILE="ft_nmap_test.log"

echo "=== ft_nmap Test Script ===" > "$LOGFILE"
date >> "$LOGFILE"
echo "" >> "$LOGFILE"

for host in "${TEST_HOSTS[@]}"; do
    echo "### Testing host: $host ###" | tee -a "$LOGFILE"
    for ports in "${PORT_RANGES[@]}"; do
        for scan in "${SCAN_TYPES[@]}"; do
            for speed in "${SPEEDUPS[@]}"; do
                echo "-------------------------------------------------" | tee -a "$LOGFILE"
                echo "Host: $host | Ports: $ports | Scan: $scan | Threads: $speed" | tee -a "$LOGFILE"
                CMD="$FT_NMAP --ip $host --ports $ports --scan $scan --speedup $speed"
                echo "Running: $CMD" >> "$LOGFILE"
                $CMD >> "$LOGFILE" 2>&1
                echo "Done." | tee -a "$LOGFILE"
            done
        done
    done
done

echo ""
echo "=== Test Completed ==="
echo "Full log saved in $LOGFILE"
