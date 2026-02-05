#!/bin/bash

DOMAIN="$1"
OUTDIR="recon_urls_$DOMAIN"

if [ -z "$DOMAIN" ]: then
    echo "Usage: $0 <domain>"
    exit 1
fi

if [ -z "$github_token" ]; then
    echo "Set Github token first: export github_token=YOUR_TOKEN"
    exit 1
fi

mkdir -p "$OUTDIR"

echo "[+] waybackurls..."
echo "$DOMAIN" | waybackurls > "$OUTDIR/waybackurls.txt"

echo "[+] gau..."
echo "$DOMAIN" | gau > "$OUTDIR/gau.txt"

echo "[+] paramspider..."
paramspider -d "$DOMAIN"
mv "results/$DOMAIN.txt" "$OUTDIR/paramspider.txt"
rm -rf "results/"

echo "[+] github-endpoints..."
github-endpoints -d "$DOMAIN" -t "$github_token" -o "$OUTDIR/github-endpoints_urls.txt"