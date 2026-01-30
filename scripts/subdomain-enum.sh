#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi

DOMAIN="$1"
OUTDIR="recon_$DOMAIN"
EXTRA_INFO_DIR="$OUTDIR/extra-info"

mkdir -p "$OUTDIR"
mkdir -p "$EXTRA_INFO_DIR"

echo "[+] Running theHarvester..."
theHarvester -d "$DOMAIN" -b all -f theharvester
mv theharvester.* "$OUTDIR/" 2>/dev/null

# Extracting theHarvester JSON data
HARVEST_JSON="$OUTDIR/theharvester.json"

if [ -f "$HARVEST_JSON" ]; then
    jq -r '.hosts[]?' "$HARVEST_JSON" | cut -d ':' -f1 | sort -u > "$OUTDIR/theharvester_hosts.txt"
    jq -r '.emails[]?' "$HARVEST_JSON" | sort -u > "$EXTRA_INFO_DIR/theharvester_emails.txt"
    jq -r '.asns[]?' "$HARVEST_JSON" | sort -u > "$EXTRA_INFO_DIR/theharvester_asns.txt"
    jq -r '.ips[]?' "$HARVEST_JSON" | sort -u > "$EXTRA_INFO_DIR/theharvester_ips.txt"
    jq -r '.interesting_urls[]?' "$HARVEST_JSON" | sort -u > "$EXTRA_INFO_DIR/urls_theharvester.txt"
fi

echo "[+] Running Sublist3r..."
sublist3r -d "$DOMAIN" -o "$OUTDIR/sublist3r.txt"

echo "[+] Running Assetfinder..."
assetfinder --subs-only "$DOMAIN" > "$OUTDIR/assetfinder.txt"

echo "[+] Fetching crt.sh subdomains..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
| jq -r '.[].name_value' \
| sed 's/\\n/\n/g' \
| grep -vF '*.' \
| sort -u > "$OUTDIR/crtsh.txt"

echo "[+] Running github-subdomains..."
github-subdomains.py -d "$DOMAIN" 2>/dev/null > "$OUTDIR/github-subdomains.txt"

echo "[+] Running findomain..."
findomain -t "$DOMAIN" -u "$OUTDIR/findomain.txt"

echo "[+] Running Amass..."
amass enum -passive -d "$DOMAIN" -nocolor -o "$EXTRA_INFO_DIR/amass_raw.txt"
awk '/\(FQDN\)/ {print $1}' "$EXTRA_INFO_DIR/amass_raw.txt" | sort -u > "$OUTDIR/amass.txt"

echo "[+] Combining and deduplicating all subdomains..."
cat "$OUTDIR"/*.txt 2>/dev/null | sort -u > "$OUTDIR/all_subdomains.txt"

echo "[+] Checking resolvable subdomains..."
dnsx -l "$OUTDIR/all_subdomains.txt" -silent -a -resp-only > "$OUTDIR/live_subdomains.txt"

echo "[+] Done. Output in $OUTDIR"
