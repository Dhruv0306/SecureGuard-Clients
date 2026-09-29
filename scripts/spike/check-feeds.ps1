# Phase 5.3 spike, Test 1: do the abuse.ch feeds need an Auth-Key?
# Usage: .\scripts\spike\check-feeds.ps1
#        $env:ABUSE_CH_AUTH_KEY = "xxxx"; .\scripts\spike\check-feeds.ps1   (also tries with key)
# Uses curl.exe on purpose: in Windows PowerShell 5.1 plain "curl" is an alias.

$ua = "ureq/3.4"   # mimic the default User-Agent of the ureq client the app uses
$feeds = @(
    @{ Name = "Feodo recommended IPs";        Url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" },
    @{ Name = "MalwareBazaar recent SHA256";  Url = "https://bazaar.abuse.ch/export/txt/sha256/recent/" }
)
$key = $env:ABUSE_CH_AUTH_KEY
$tmp = [System.IO.Path]::GetTempFileName()

function Test-Feed($name, $url, $mode) {
    $curlArgs = @("-sS", "-L", "-m", "30", "-A", $ua, "-o", $tmp, "-w", "%{http_code}")
    if ($mode -eq "with key") { $curlArgs += @("-H", "Auth-Key: $key") }
    $code = & curl.exe @curlArgs $url
    $lines = @(Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue)
    $data = @($lines | Where-Object { $_ -and -not $_.StartsWith("#") })
    $colon = @($data | Where-Object { $_.Contains(":") })
    "{0,-30} {1,-9} HTTP {2,-4} lines={3} data={4} data-with-colon={5}" -f $name, $mode, $code, $lines.Count, $data.Count, $colon.Count
    "  first data lines:"
    $data | Select-Object -First 3 | ForEach-Object { "    $_" }
}

foreach ($f in $feeds) {
    Test-Feed $f.Name $f.Url "no key"
    if ($key) { Test-Feed $f.Name $f.Url "with key" }
}
Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
""
"200 = usable. 401/403 = key required. 429 = rate limited. HTML/JSON body = parser would misread it."
