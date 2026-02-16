#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <root-domain>"
    exit 1
fi

DOMAIN="$1"
SUBDOMAINSDIR="$HOME/Desktop/y0uss3ff/bug-hunting/targets/$DOMAIN/recon_$DOMAIN" # Change this with the path of your subdomains

HTTPX_FILE="$SUBDOMAINSDIR/alive_httpx.txt"
if [ ! -f "$HTTPX_FILE" ]; then
    echo "alive_httpx.txt not found in $SUBDOMAINSDIR"
    exit 1
fi

if [ -z "$github_token" ]; then
    echo "Set Github token first: export github_token=YOUR_TOKEN"
    exit 1
fi

OUTDIR="$HOME/Desktop/y0uss3ff/bug-hunting/targets/$DOMAIN/recon_urls_$DOMAIN" # Change this with the path you wish to have the output in
mkdir -p "$OUTDIR"
mkdir -p "$OUTDIR/temp"

echo "[+] Extracting live URLs from httpx output"

sed -r 's/\x1B\[[0-9;]*[mGKH]//g' "$HTTPX_FILE" \
| awk '/\[(200|301|302|403)\]/ {print $1}' \
| sort -u > "$OUTDIR/temp/live_urls.txt"

if [ ! -s "$OUTDIR/temp/live_urls.txt" ]; then
    echo "No live URLs after filtering. Check httpx output."
    exit 1
fi

sed -E 's#^https?://##' "$OUTDIR/temp/live_urls.txt" | cut -d'/' -f1 | sort -u > "$OUTDIR/temp/domains.txt"

echo "[+] waybackurls"
cat "$OUTDIR/temp/domains.txt" | waybackurls > "$OUTDIR/wayback.txt"

echo "[+] gau"
cat "$OUTDIR/temp/domains.txt" | gau --threads 5 > "$OUTDIR/gau.txt"

echo "[+] urlfinder"
urlfinder -list "$OUTDIR/temp/domains.txt" -all -ns -silent -o "$OUTDIR/urlfinder.txt"

echo "[+] github-endpoints"
github-endpoints -d "$DOMAIN" -t "$github_token" -o "$OUTDIR/github-endpoints_urls.txt"

echo "[+] katana crawling live hosts"
katana -list "$OUTDIR/temp/live_urls.txt" -silent -depth 3 -jc -o "$OUTDIR/katana.txt"

echo "[+] gospider"
gospider -S "$OUTDIR/temp/live_urls.txt" -d 2 -c 10 -t 10 --other-source --include-subs -o "$OUTDIR/gospider"
cat "$OUTDIR/gospider"/* > "$OUTDIR/all_gospider_output.txt"

DOMAIN_ESCAPED=$(printf '%s\n' "$DOMAIN" | sed 's/\./\\./g')

grep -oE 'https?://[^ ]+' "$OUTDIR/all_gospider_output.txt" \
| sed 's/[")>\]]*$//' \
| tr '[:upper:]' '[:lower:]' \
| grep -E "^https?://([a-z0-9-]+\.)*$DOMAIN_ESCAPED(/|$)" \
| grep -Ev 'github\.com|reactjs\.org|w3\.org' \
| grep -Ev '/(DD|MM|YYYY|text|application)/' \
| sort -u > "$OUTDIR/gospider.txt"

rm -rf "$OUTDIR/gospider/" "$OUTDIR/all_gospider_output.txt"

echo "[+] Combining URLs"
cat "$OUTDIR"/*.txt | sort -u > "$OUTDIR/all_urls.txt"
rm  "$OUTDIR/wayback.txt" "$OUTDIR/urlfinder.txt" "$OUTDIR/gau.txt" "$OUTDIR/katana.txt" "$OUTDIR/github-endpoints_urls.txt" "$OUTDIR/gospider.txt"

echo "[+] Cleaning URLs (uro)"
uro -i "$OUTDIR/all_urls.txt" -o "$OUTDIR/clean_urls.txt"
rm "$OUTDIR/all_urls.txt"

echo "[+] Extracting JS files"
grep -Ei "\.js($|\?|#)" "$OUTDIR/clean_urls.txt" | sort -u > "$OUTDIR/js_urls.txt"

echo "[+] Extracting endpoints from JS (LinkFinder with source mapping)"

> "$OUTDIR/js_endpoints.txt"

while read -r js_url; do
    echo "===== $js_url =====" >> "$OUTDIR/js_endpoints.txt"
    linkfinder -i "$js_url" -o cli 2>/dev/null \
        | sed "s|^|[$js_url] |" >> "$OUTDIR/js_endpoints.txt"
    echo "" >> "$OUTDIR/js_endpoints.txt"
done < "$OUTDIR/js_urls.txt"

awk '
{
    buf[NR]=$0
}

/Error/ {
    del[NR]=1
    del[NR-1]=1
    del[NR-2]=1
    del[NR-3]=1
}

END {
    for(i=1;i<=NR;i++)
        if(!del[i]) print buf[i]
}
' "$OUTDIR/js_endpoints.txt" > "$OUTDIR/js_endpoints_clean.txt"

rm "$OUTDIR/js_endpoints.txt"

echo "[+] Secret hunting from JS (Mantra)"
cat "$OUTDIR/js_urls.txt" | mantra > "$OUTDIR/mantra_secrets.txt"

echo "[+] Secret hunting from JS (SecretFinder)"
while read -r js_url; do
    secretfinder -i "$js_url" -o cli >> "$OUTDIR/secretfinder_secrets.txt"
done < "$OUTDIR/js_urls.txt"

echo "[+] Aquatone"
mkdir -p "$OUTDIR/aquatone"
cat "$OUTDIR/temp/domains.txt" | aquatone -out "$OUTDIR/aquatone"

echo "[+] Possible SSRF"
cat "$OUTDIR/clean_urls.txt" | gf ssrf > "$OUTDIR/gf_ssrf.txt"

echo "[+] Possible SQLi"
cat "$OUTDIR/clean_urls.txt" | gf sqli > "$OUTDIR/gf_sqli.txt"

echo "[+] Possible IDOR"
cat "$OUTDIR/clean_urls.txt" | gf idor > "$OUTDIR/gf_idor.txt"

echo "[+] Possible LFI"
cat "$OUTDIR/clean_urls.txt" | gf lfi > "$OUTDIR/gf_lfi.txt"

echo "[+] Possible Redirect"
cat "$OUTDIR/clean_urls.txt" | gf redirect > "$OUTDIR/gf_redirect.txt"

echo "[+] Possible XSS"
cat "$OUTDIR/clean_urls.txt" | gf xss > "$OUTDIR/gf_xss.txt"

echo "[+] DONE — URLs, JS endpoints, secrets extracted."

