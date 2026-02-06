#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

SUBDOMAINSDIR="recon_$DOMAIN"

if [ ! -f "$SUBDOMAINSDIR/httpx_results.txt" ]; then
    echo "httpx_results.txt not found"
    exit 1
fi

INPUTDIR="$SUBDOMAINSDIR/httpx_results.txt"
OUTDIR="recon_urls"
mkdir -p "$OUTDIR"

if [ -z "$github_token" ]; then
    echo "Set Github token first: export github_token=YOUR_TOKEN"
    exit 1
fi

echo "[+] waybackurls"
cat "$INPUTDIR" | waybackurls > "$OUTDIR/wayback.txt"

echo "[+] gau"
cat "$INPUTDIR" | gau --threads 5 > "$OUTDIR/gau.txt"

echo "[+] github-endpoints" github-endpoints -d "$DOMAIN" -t "$github_token" -o "$OUTDIR/github-endpoints_urls.txt"

# this one uses domains not urls
echo "[+] urlfinder"
urlfinder -list domains_from_httpx.txt -all -ns -silent -o "$OUTDIR/urlfinder.txt"

echo "[+] katana crawling live hosts"
katana -list "$INPUTDIR" -silent -depth 3 -jc -o "$OUTDIR/katana.txt"

echo "[+] gospider"
gospider -S "$INPUTDIR" -d 2 -c 10 -t 10 --other-source --include-subs -o "$OUTDIR/gospider"

echo "[+] Combining URLs"
cat "$OUTDIR"/.txt | sort -u > "$OUTDIR/all_urls.txt"

echo "[+] Cleaning URLs"
uro -i "$OUTDIR/all_urls.txt" -o "$OUTDIR/clean_urls.txt"

echo "[+] Aquatone"
cat "$OUTDIR/clean_urls.txt" | aquatone -out "$OUTDIR/aquatone"

echo "[+] Extracting JS files"
grep -Ei "\.js($|\?|#)" "$OUTDIR/clean_urls.txt" | sort -u > "$OUTDIR/js_urls.txt"

echo "[+] Extracting endpoints from JS (LinkFinder)"
linkfinder -i "$OUTDIR/js_urls.txt" -o cli > "$OUTDIR/js_endpoints.txt" # Python script not a tool

echo "[+] Secret hunting — Mantra"
cat "$OUTDIR/js_urls.txt" | mantra > "$OUTDIR/mantra.txt"

echo "[+] Secret hunting from js (SecretFinder)"
secretfinder -i "$OUTDIR/js_urls.txt" -o cli > "$OUTDIR/secretfinder.txt" # Python script not a tool
cat "$OUTDIR/mantra.txt" "$OUTDIR/secretfinder.txt" | sort -u > "$OUTDIR/fullsecrets.txt"
rm "$OUTDIR/mantra.txt" "$OUTDIR/secretfinder.txt"

echo "[+] Possible ssrf"
cat "$OUTDIR/clean_urls" | gf ssrf > "$OUTDIR/gf_ssrf.txt"

echo "[+] Possible sqli"
cat "$OUTDIR/clean_urls" | gf sqli > "$OUTDIR/gf_sqli.txt"

echo "[+] Possible idor"
cat "$OUTDIR/clean_urls" | gf idor > "$OUTDIR/gf_idor.txt"

echo "[+] Possible lfi"
cat "$OUTDIR/clean_urls" | gf lfi > "$OUTDIR/gf_lfi.txt"

echo "[+] Possible redirect"
cat "$OUTDIR/clean_urls" | gf redirect > "$OUTDIR/gf_redirect.txt"

echo "[+] DONE — URLs, JS endpoints, secrets extracted."
