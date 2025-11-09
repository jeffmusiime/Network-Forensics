#!/bin/bash
# Automated PCAP Analyzer using tshark

# Author: Joel J. Musiime

#To Use
#chmod +x analyze_pcap.sh

#./analyze_pcap.sh sample_traffic.pcap

#1.Check dependencies
check_tshark() {
  if ! command -v tshark &> /dev/null; then
    echo "[INFO] tshark not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
      if command -v brew &> /dev/null; then
        brew install wireshark
      else
        echo "[ERROR] Homebrew not found. Install it from https://brew.sh/"
        exit 1
      fi
    elif [[ -f /etc/debian_version ]]; then
      sudo apt update && sudo apt install -y tshark
    else
      echo "[ERROR] Unsupported OS. Please install tshark manually."
      exit 1
    fi
  else
    echo "[OK] tshark is installed."
  fi
}

#2.Validate input
if [ $# -ne 1 ]; then
  echo "Usage: $0 <file.pcap>"
  exit 1
fi

PCAP_FILE="$1"
if [ ! -f "$PCAP_FILE" ]; then
  echo "[ERROR] File '$PCAP_FILE' not found."
  exit 1
fi

#3. Setup output directories
BASENAME=$(basename "$PCAP_FILE" .pcap)
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
OUTDIR="analysis_results/${TIMESTAMP}_${BASENAME}"
mkdir -p "$OUTDIR"

#4. Check tshark
check_tshark

echo "[INFO] Starting analysis on $PCAP_FILE..."
sleep 1

#5. Run analysis
echo "[INFO] Generating summaries..."
tshark -r "$PCAP_FILE" -q -z io,stat,1 > "$OUTDIR/${BASENAME}_summary.txt"
tshark -r "$PCAP_FILE" -q -z conv,ip > "$OUTDIR/${BASENAME}_conversations.txt"

echo "[INFO] Extracting DNS traffic..."
tshark -r "$PCAP_FILE" -Y "dns" -T fields -E header=y -E separator=, \
  -e frame.time -e ip.src -e dns.qry.name -e dns.flags.rcode \
  > "$OUTDIR/${BASENAME}_dns.csv"

echo "[INFO] Extracting HTTP traffic..."
tshark -r "$PCAP_FILE" -Y "http.request" -T fields -E header=y -E separator=, \
  -e frame.time -e ip.src -e http.host -e http.request.uri -e http.user_agent \
  > "$OUTDIR/${BASENAME}_http.csv"

echo "[INFO] Extracting TLS handshake info..."
tshark -r "$PCAP_FILE" -Y "tls.handshake.extensions_server_name" -T fields -E header=y -E separator=, \
  -e frame.time -e ip.dst -e tls.handshake.extensions_server_name \
  > "$OUTDIR/${BASENAME}_tls.csv"

echo "[INFO] Checking for anomalies..."
tshark -r "$PCAP_FILE" -q -z expert > "$OUTDIR/${BASENAME}_alerts.txt"

#6. Anomaly detection (grep patterns)
ANOMALY_REPORT="$OUTDIR/${BASENAME}_anomalies.txt"
echo "[INFO] Running anomaly scan..." 
{
  echo "==== Potential Anomalies Detected ===="
  grep -iE "malformed|error|retransmission|bad checksum|invalid|suspicious" "$OUTDIR/${BASENAME}_alerts.txt" || echo "No critical anomalies found."
  echo ""
  echo "==== Uncommon Ports (above 1024, not standard HTTP/DNS/HTTPS) ===="
  tshark -r "$PCAP_FILE" -T fields -e tcp.dstport | grep -E '^[0-9]+$' | awk '$1>1024 && $1!=8080 && $1!=8443 && $1!=5353' | sort | uniq -c | sort -nr | head -n 10
  echo ""
  echo "==== Repeated Failed DNS Queries ===="
  grep ",3$" "$OUTDIR/${BASENAME}_dns.csv" | cut -d',' -f3 | sort | uniq -c | sort -nr | head -n 10
} > "$ANOMALY_REPORT"

#7.Summary
echo "[DONE] Analysis complete. Results stored in: $OUTDIR"
echo
echo "Key output files:"
echo " - ${BASENAME}_summary.txt ........ General statistics"
echo " - ${BASENAME}_conversations.txt .. Top IPs and flows"
echo " - ${BASENAME}_dns.csv ............ DNS activity"
echo " - ${BASENAME}_http.csv ........... HTTP requests"
echo " - ${BASENAME}_tls.csv ............ TLS handshakes"
echo " - ${BASENAME}_alerts.txt ......... tshark expert warnings"
echo " - ${BASENAME}_anomalies.txt ...... Highlighted anomalies"
echo
echo "Tip: Open CSVs with Excel or pandas for deeper analysis."

