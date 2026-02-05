#!/bin/bash
set -e

if [ -z "$1" ]; then exit 1; fi

DOMAIN="$1"
OUTDIR="recon_$DOMAIN"
EXTRA="$OUTDIR/extra-info"

WORDLIST="/usr/share/wordlists/SecLists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt"
RESOLVERS="/opt/offensive-tools/recon-tools/massdns/lists/resolvers.txt"
MASSDNS="massdns"

mkdir -p "$OUTDIR" "$EXTRA"

echo "[+] theHarvester"
theHarvester -d "$DOMAIN" -b all -f theharvester || true
mv theharvester.* "$OUTDIR/" 2>/dev/null || true

HARVEST_JSON="$OUTDIR/theharvester.json"
if [ -f "$HARVEST_JSON" ]; then
echo "[+] Extracting theHarvester data"
jq -r '.hosts[]?' "$HARVEST_JSON" | cut -d ':' -f1 | sort -u > "$OUTDIR/theharvester_hosts.txt"
jq -r '.emails[]?' "$HARVEST_JSON" | sort -u > "$EXTRA/theharvester_emails.txt"
jq -r '.asns[]?' "$HARVEST_JSON" | sort -u > "$EXTRA/theharvester_asns.txt"
jq -r '.ips[]?' "$HARVEST_JSON" | sort -u > "$EXTRA/theharvester_ips.txt"
jq -r '.interesting_urls[]?' "$HARVEST_JSON" | sort -u > "$EXTRA/theharvester_urls.txt"
fi

echo "[+] Sublist3r"
sublist3r -d "$DOMAIN" -o "$OUTDIR/sublist3r.txt" || true

echo "[+] Assetfinder"
assetfinder --subs-only "$DOMAIN" > "$OUTDIR/assetfinder.txt"

echo "[+] Subfinder"
subfinder -silent -d "$DOMAIN" > "$OUTDIR/subfinder.txt"

echo "[+] Findomain"
findomain -t "$DOMAIN" -u "$OUTDIR/findomain.txt" || true

echo "[+] crt.sh"
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
| jq -r '.[].name_value' | sed 's/\\n/\n/g' | grep -vF '*.' | sort -u > "$OUTDIR/crtsh.txt"

echo "[+] github-subdomains..."
github-subdomains -d "$DOMAIN" -t "$github_token" -o "$OUTDIR/github-subdomains.txt"

echo "[+] Amass passive"
amass enum -passive -d "$DOMAIN" -nocolor -o "$EXTRA/amass_raw.txt" || true
awk '/\(FQDN\)/ {print $1}' "$EXTRA/amass_raw.txt" | sort -u > "$OUTDIR/amass.txt"

echo "[+] Combining passive results"
cat "$OUTDIR"/*.txt 2>/dev/null | sort -u | grep "\.$DOMAIN$" > "$OUTDIR/passive.txt"

echo "[+] Massdns level 1 bruteforce"
sed "s/$/.$DOMAIN/" "$WORDLIST" > "$OUTDIR/bruteforce_lvl1.txt"
$MASSDNS -r "$RESOLVERS" -t A -o S "$OUTDIR/bruteforce_lvl1.txt" | awk '{print $1}' | sed 's/\.$//' | sort -u > "$OUTDIR/massdns_lvl1.txt"

echo "[+] Merging level 1"
cat "$OUTDIR/passive.txt" "$OUTDIR/massdns_lvl1.txt" | sort -u > "$OUTDIR/level1.txt"

echo "[+] Preparing deep bruteforce"
head -n 500 "$OUTDIR/level1.txt" > "$OUTDIR/deep_base.txt"
> "$OUTDIR/deep_candidates.txt"
while read sub; do awk -v base="$sub" '{print $0"."base}' "$WORDLIST"; done < "$OUTDIR/deep_base.txt" >> "$OUTDIR/deep_candidates.txt"

echo "[+] Massdns deep bruteforce"
$MASSDNS -r "$RESOLVERS" -t A -o S "$OUTDIR/deep_candidates.txt" | awk '{print $1}' | sed 's/\.$//' | sort -u > "$OUTDIR/massdns_deep.txt"

echo "[+] Merging deep results"
cat "$OUTDIR/level1.txt" "$OUTDIR/massdns_deep.txt" | sort -u > "$OUTDIR/all_subs.txt"

echo "[+] Generating permutations (dnsgen)"
dnsgen "$OUTDIR/all_subs.txt" > "$OUTDIR/permutations.txt" 2>/dev/null || true

echo "[+] Resolving permutations"
$MASSDNS -r "$RESOLVERS" -t A -o S "$OUTDIR/permutations.txt" | awk '{print $1}' | sed 's/\.$//' | sort -u >> "$OUTDIR/all_subs.txt"

echo "[+] Final dedupe"
sort -u "$OUTDIR/all_subs.txt" > "$OUTDIR/final_subdomains.txt"

echo "[+] DNS resolution (dnsx)"
dnsx -l "$OUTDIR/final_subdomains.txt" -silent -a -resp-only > "$OUTDIR/resolved.txt"

echo "[+] HTTP probing (httpx)"
httpx -l "$OUTDIR/resolved.txt" -silent -title -status-code -tech-detect -server -ip > "$OUTDIR/alive_http.txt"

echo "[+] Extracting IPs for port scan"
awk '{print $NF}' "$OUTDIR/alive_http.txt" | sort -u > "$OUTDIR/ips.txt"

echo "[+] Masscan port scanning"
PORTS="80,81-89,443,444,8000-8100,8080-8090,8180,8443,8888,9000-9010,9443,10443"
masscan -p$PORTS -iL "$OUTDIR/ips.txt" --rate 10000 -oG "$OUTDIR/masscan.gnmap" || true

echo "[+] Parsing masscan results"
awk '/Ports:/{split($0,a," "); ip=a[2]; gsub("Host:","",ip);
for(i=1;i<=NF;i++){if($i ~ /^[0-9]+\/open/){split($i,p,"/"); print ip ":" p[1]}}}' "$OUTDIR/masscan.gnmap" > "$OUTDIR/ip_ports.txt"

echo "[+] Probing discovered ports with httpx"
httpx -l "$OUTDIR/ip_ports.txt" -silent -title -status-code -tech-detect -server > "$OUTDIR/alive_nonstandard_ports.txt"

echo "[+] Merging all alive web services"
cat "$OUTDIR/alive_http.txt" "$OUTDIR/alive_nonstandard_ports.txt" | sort -u > "$OUTDIR/final_alive_assets.txt"

echo "Recon finished for $DOMAIN"
