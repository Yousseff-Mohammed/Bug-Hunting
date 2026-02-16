#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

if [ -z "$github_token" ]; then
    echo "Github token not set."
    echo "run export github_token=YOUR_TOKEN"
    exit 1
fi

DOMAIN="$1"
mkdir -p "$HOME/Desktop/y0uss3ff/bug-hunting/targets/$DOMAIN"
OUTDIR="$HOME/Desktop/y0uss3ff/bug-hunting/targets/$DOMAIN/recon_$DOMAIN" # Change this with your preferred output path
TEMP="$OUTDIR/temp"
WORDLIST="/usr/share/wordlists/SecLists/Discovery/DNS/best-dns-wordlist.txt" # Change this with the wordlist that you wish to use for brute forcing
RESOLVERS="/usr/share/wordlists/SecLists/Discovery/DNS/resolvers/resolvers-trusted.txt" # Change this with resolvers txt file path
DNS_PERMS="/usr/share/wordlists/SecLists/Discovery/DNS/perms/dns_perms.txt" # Change this with permutations list that you wish to use

mkdir -p "$OUTDIR" "$TEMP"

echo "[+] theHarvester"
theHarvester -d "$DOMAIN" -b all -f theharvester || true
mv theharvester.* "$OUTDIR/" 2>/dev/null || true

HARVEST_JSON="$OUTDIR/theharvester.json"
if [ -f "$HARVEST_JSON" ]; then
echo "[+] Extracting theHarvester data"
jq -r '.hosts[]?' "$HARVEST_JSON" | cut -d ':' -f1 | sort -u > "$OUTDIR/theharvester_hosts.txt"
jq -r '.emails[]?' "$HARVEST_JSON" | sort -u > "$TEMP/theharvester_emails.txt"
jq -r '.asns[]?' "$HARVEST_JSON" | sort -u > "$TEMP/theharvester_asns.txt"
jq -r '.ips[]?' "$HARVEST_JSON" | sort -u > "$TEMP/theharvester_ips.txt"
jq -r '.interesting_urls[]?' "$HARVEST_JSON" | sort -u > "$TEMP/theharvester_urls.txt"
fi
rm "$OUTDIR"/theharvester.*

echo "[+] Sublist3r"
sublist3r -d "$DOMAIN" -o "$OUTDIR/sublist3r.txt"

echo "[+] Assetfinder"
assetfinder --subs-only "$DOMAIN" > "$OUTDIR/assetfinder.txt"

echo "[+] Subfinder"
subfinder -silent -d "$DOMAIN" > "$OUTDIR/subfinder.txt"

echo "[+] Findomain"
findomain -t "$DOMAIN" -u "$OUTDIR/findomain.txt"

echo "[+] crt.sh"
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
| jq -r '.[].name_value' | sed 's/\\n/\n/g' | grep -vF '*.' | sort -u > "$OUTDIR/crtsh.txt"
crt.sh $DOMAIN
mv "$HOME/result_directory/$DOMAIN.crt.txt" "$TEMP/crtsh.txt"
cat "$TEMP/crtsh.txt" \
| tr '[:upper:]' '[:lower:]' \
| sed -E 's#https?://##g; s#\*\.##g; s#^[^@]*@##g#' \
| grep -Eo "([a-z0-9-]+\.)+$DOMAIN" \
| sort -u > "$OUTDIR/crtsh.txt"

echo "[+] github-subdomains"
github-subdomains -d "$DOMAIN" -t "$github_token" -o "$OUTDIR/github-subdomains.txt"

echo "[+] Amass passive"
amass enum -timeout 15 -passive -d "$DOMAIN" -nocolor -o "$TEMP/amass_raw.txt"

awk -v d="$DOMAIN" '/\(FQDN\)/ {print $1}' "$TEMP/amass_raw.txt" \
| grep -E "(\.|^)$DOMAIN$" \
| sort -u > "$OUTDIR/amass.txt"

echo "[+] Validating dns resolvers"
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o "$TEMP/resolvers1.txt"
dnsvalidator -tL $RESOLVERS -threads 100 -o "$TEMP/resolvers2.txt"

cat "$TEMP/resolvers1.txt" "$TEMP/resolvers2.txt" | sort -u > "$TEMP/final_resolvers.txt"

echo "[+] Active enumeration"
puredns bruteforce "$WORDLIST" "$DOMAIN" -r "$TEMP/final_resolvers.txt" -w "$OUTDIR/puredns.txt"
cat "$OUTDIR"/*.txt | sort -u > "$OUTDIR/found_subs.txt"
rm "$OUTDIR/amass.txt" "$OUTDIR/findomain.txt" "$OUTDIR/crtsh.txt" "$OUTDIR/github-subdomains.txt" \
"$OUTDIR/subfinder.txt" "$OUTDIR/assetfinder.txt" "$OUTDIR/sublist3r.txt" "$OUTDIR/theharvester_hosts.txt" \
"$OUTDIR/puredns.txt"

echo "[+] Permutations"
gotator -sub "$OUTDIR/found_subs.txt" -perm "$DNS_PERMS" -depth 1 -numbers 10 -mindup -adv -md \
| sort -u > "$TEMP/perms.txt"

puredns resolve "$TEMP/perms.txt" -r "$TEMP/final_resolvers.txt" > "$OUTDIR/resolved_perms.txt"

echo "[+] Combining results"
cat "$OUTDIR"/*.txt | sort -u > "$OUTDIR/all_subs.txt"

echo "[+] Recursive enumeration"
> "$OUTDIR/passive_recursive.txt"
for sub in $( (cat "$OUTDIR/all_subs.txt" | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 \
&& cat "$OUTDIR/all_subs.txt" | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10) \
| sed 's/^[[:space:]]*//' | cut -d ' ' -f2 ); do

    subfinder -d "$sub" -silent -max-time 2 | anew -q "$OUTDIR/passive_recursive.txt"
    assetfinder --subs-only "$sub" | anew -q "$OUTDIR/passive_recursive.txt"
    amass enum -timeout 3 -passive -d "$sub" -nocolor -o "$TEMP/amass_recursive_raw.txt"
    awk -v d="$DOMAIN" '/\(FQDN\)/ {print $1}' "$TEMP/amass_recursive_raw.txt" \
    | grep -E "(\.|^)$DOMAIN$" \
    | sort -u \
    | anew -q "$OUTDIR/passive_recursive.txt"
    findomain -q -t "$sub" | anew -q "$OUTDIR/passive_recursive.txt"
done

echo "[+] Final dedupe"
sort -u "$OUTDIR/all_subs.txt" "$OUTDIR/passive_recursive.txt" > "$OUTDIR/final_subdomains.txt"
rm "$OUTDIR/all_subs.txt" "$OUTDIR/passive_recursive.txt"

echo "[+] DNS resolution (dnsx)"
dnsx -l "$OUTDIR/final_subdomains.txt" -silent -a -retry 3 -resp-only > "$OUTDIR/dnsx_ips.txt"

echo "[+] HTTP probing (httpx)"
httpx -l "$OUTDIR/final_subdomains.txt" -silent -title -status-code -tech-detect -server -ip > "$OUTDIR/alive_httpx.txt"

echo "[+] Extracting IPs for port scan"
grep -oP '\[(?:\d{1,3}\.){3}\d{1,3}\]' "$OUTDIR/alive_httpx.txt" | tr -d '[]' | sort -u > "$OUTDIR/httpx_ips.txt"

cat "$OUTDIR/httpx_ips.txt" "$OUTDIR/dnsx_ips.txt" | sort -u > "$OUTDIR/final_ips.txt"
rm "$OUTDIR/httpx_ips.txt" "$OUTDIR/dnsx_ips.txt"

echo "[+] Masscan port scanning"
PORTS="1-79,81-442,444,65535"
masscan -p$PORTS -iL "$OUTDIR/final_ips.txt" --rate 10000 -oG "$OUTDIR/masscan.gnmap"

echo "[+] Parsing masscan results"
awk '/Host:/{split($7,a,"/"); print $4":"a[1]}' "$OUTDIR/masscan.gnmap" > "$OUTDIR/ip_ports.txt"
rm "$OUTDIR/masscan.gnmap"

echo "[+] Probing discovered ports with httpx"
httpx -l "$OUTDIR/ip_ports.txt" -silent -title -status-code -tech-detect -server > "$OUTDIR/alive_nonstandard_ports.txt"

echo "[+] Testing for subdomain takeover"
subzy run --targets "$OUTDIR/final_subdomains.txt" --output "$OUTDIR/subzy-takeovers.json"

nuclei -l "$OUTDIR/final_subdomains.txt" -t "$HOME/nuclei-templates/dns/detect-all-takeovers.yaml" -o "$OUTDIR/nuclei-takeovers.txt"

echo "Recon finished for $DOMAIN"
