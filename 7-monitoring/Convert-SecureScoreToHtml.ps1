<#
Secure Score dashboard for Microsoft Graph secureScores JSON.

What's included
- Big donut with OVERALL % centered + earned/total points under it
- Category completion bars (Identity, Data, Apps, Devices)
- Risk bar with % in “Your Business” and “Organizations of a similar size” bubbles
- Top-3 “To be addressed” per category (from controlScores)

JSON expected
- Graph export like: { "value": [ { createdDateTime, currentScore, maxScore, averageComparativeScores, controlScores: [...] }, ... ] }

Run examples
.\Convert-GraphSecureScoresToHtml.v3.3.ps1 -Open
.\Convert-GraphSecureScoresToHtml.v3.3.ps1 -InputJsonPath 'C:\path\secure-score.json' -Force -Open
#>

[CmdletBinding()]
param(
  [string]$InputJsonPath,
  [string]$OutputHtmlPath = (Join-Path $PSScriptRoot 'secure-score-dashboard.html'),

  [string]$Title = 'Secure Score',
  [string]$Description = "The Secure Score is a reflection of your organization's security posture. It measures how well your organization is leveraging Microsoft 365 security features. The score is calculated based on enabled security features and actions taken to protect your organization. The higher the score, the more secure your organization is.",

  [ValidateRange(1,100)]
  [int]$JsonDepth = 100,

  [switch]$Force,
  [switch]$AutoVersion,
  [switch]$Open
)

# ---------- Helpers ----------
function Resolve-PathSmart {
  param([string]$Path,[string]$DefaultFileName,[string]$Purpose)
  $c=@()
  if ([string]::IsNullOrWhiteSpace($Path)) {
    if ($DefaultFileName) {
      if ($PSScriptRoot){ $c += (Join-Path $PSScriptRoot $DefaultFileName) }
      $c += (Join-Path (Get-Location) $DefaultFileName)
    }
  } else {
    $c += $Path
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
      if ($PSScriptRoot){ $c += (Join-Path $PSScriptRoot $Path) }
      $c += (Join-Path (Get-Location) $Path)
    }
  }
  foreach($p in $c){ if($p -and (Test-Path -LiteralPath $p)){ return (Resolve-Path -LiteralPath $p).Path } }
  throw "$Purpose not found. Tried:`n - " + ($c -join "`n - ")
}
function Read-TextBOMSafe { param([Parameter(Mandatory=$true)][string]$Path)
  $sr=[System.IO.StreamReader]::new($Path,$true); try{$t=$sr.ReadToEnd()}finally{$sr.Dispose()}
  $t.TrimStart([char]0xFEFF)
}
function Read-JsonFile { param([Parameter(Mandatory=$true)][string]$Path)
  try { (Read-TextBOMSafe -Path $Path) | ConvertFrom-Json -ErrorAction Stop }
  catch { throw "Failed to parse JSON '$Path'. Error: $($_.Exception.Message)" }
}
function New-UniquePath { param([Parameter(Mandatory=$true)][string]$Path)
  $dir=Split-Path $Path -Parent; $name=Split-Path $Path -Leaf
  $base=[IO.Path]::GetFileNameWithoutExtension($name); $ext=[IO.Path]::GetExtension($name)
  do{ $candidate=Join-Path $dir "$base`_$(Get-Date -Format 'yyyyMMdd_HHmmss')$ext" } while(Test-Path -LiteralPath $candidate)
  $candidate
}

# ---------- Load Graph secureScores ----------
$ScoresPath = Resolve-PathSmart -Path $InputJsonPath -DefaultFileName 'secure-score.json' -Purpose 'Input JSON'
$root = Read-JsonFile -Path $ScoresPath
$items = if ($root.value -is [Array]) { $root.value } elseif ($root -is [Array]) { $root } else { @($root) }
if ($items.Count -eq 0) { throw "No entries found under 'value'." }

# Sort and pick latest snapshot
$items  = $items | Sort-Object { [datetime]($_.createdDateTime) }
$latest = $items[-1]

# Overall (with smart fallbacks so % is never missing)
$overallMy  = [double]($latest.currentScore)
$overallMax = [double]($latest.maxScore)
$overallPct = 0

# Parse controls (for fallbacks + categories + top-3)
$controls = @()
if ($latest.controlScores -is [Array]) {
  foreach ($c in $latest.controlScores) {
    $score = [double]$c.score
    $pct   = $null; if ($c.PSObject.Properties.Match('scoreInPercentage').Count){ $pct=[double]$c.scoreInPercentage }
    $max   = $null; if ($pct -is [double] -and $pct -gt 0){ $max = [math]::Round($score/($pct/100.0),2) }
    $controls += [pscustomobject]@{
      title=$c.controlName
      category=$c.controlCategory
      current=$score
      max=$max
      percentage=$pct
      status=$c.implementationStatus
      description=$c.description
    }
  }
}

# Overall %: primary (current/max), else weighted from controls, else avg of percentages
if ($overallMax -gt 0) {
  $overallPct = [math]::Round(($overallMy/$overallMax)*100,2)
} else {
  $sumEarned=0.0; $sumMax=0.0; $sumPct=0.0; $cntPct=0
  foreach($x in $controls){
    if ($x.max -is [double] -and $x.max -gt 0) { $sumEarned += $x.current; $sumMax += $x.max }
    if ($x.percentage -is [double]) { $sumPct += $x.percentage; $cntPct++ }
  }
  if ($sumMax -gt 0) {
    $overallPct = [math]::Round(($sumEarned/$sumMax)*100,2)
    $overallMy  = [math]::Round($sumEarned,2)
    $overallMax = [math]::Round($sumMax,2)
  } elseif ($cntPct -gt 0) {
    $overallPct = [math]::Round($sumPct/$cntPct,2)
  } else {
    $overallPct = 0
  }
}

# Averages for risk bar
$allTenants = $null; $seatAvg = $null
if ($latest.averageComparativeScores) {
  $allTenants = $latest.averageComparativeScores | Where-Object { $_.basis -eq 'AllTenants' } | Select-Object -First 1
  $seatAvg    = $latest.averageComparativeScores | Where-Object { $_.basis -eq 'TotalSeats' } | Select-Object -First 1
}
$avgOverall_AllTenants = if ($allTenants) { [double]$allTenants.averageScore } else { $null }
$avgOverall_Seats      = if ($seatAvg)    { [double]$seatAvg.averageScore }    else { $null }

# Normalized object for HTML
$normalized = [pscustomobject]@{
  OverallScores = [pscustomobject]@{
    MyScore = $overallMy
    MaxScore = $overallMax
    PercentageScore = $overallPct
    AllTenantAverage = $avgOverall_AllTenants
    SimilarSeatsAverage = $avgOverall_Seats
  }
}

# JSON blobs
$depth = [Math]::Min($JsonDepth,100)
$scoresJson   = ($normalized | ConvertTo-Json -Depth $depth -Compress) -replace '</script','<\/script'
$controlsJson = if ($controls.Count -gt 0) { ($controls | ConvertTo-Json -Depth $depth -Compress) } else { 'null' }
$controlsJson = $controlsJson -replace '</script','<\/script'

# Output path
$dir = Split-Path -Path $OutputHtmlPath -Parent
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
if (Test-Path -LiteralPath $OutputHtmlPath) {
  if ($Force) { } elseif ($AutoVersion) { $OutputHtmlPath = New-UniquePath -Path $OutputHtmlPath } else {
    throw "Output exists: $OutputHtmlPath (use -Force or -AutoVersion)"
  }
}

# ---------- HTML (donut center fix + UI) ----------
$template = @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{TITLE}}</title>
<style>
:root{--bg:#0b0b0f;--ink:#fff;--muted:#c7c9d3;--panel:#121317;--green:#22c55e;--border:rgba(255,255,255,.08)}
html,body{margin:0;padding:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial}
.wrap{max-width:1100px;margin:32px auto;padding:0 24px}
h1{font-size:56px;letter-spacing:.3px;margin:0 0 12px}
.top{display:grid;grid-template-columns:minmax(260px,340px) 1fr;gap:28px;align-items:center}

/* Donut: center % text perfectly */
.donutBox{display:grid;place-items:center}
.donut{position:relative;width:240px;aspect-ratio:1/1}
.donut::before{
  content:""; position:absolute; inset:0; border-radius:50%;
  background:conic-gradient(var(--green) calc(var(--pct)*1%), #1f2a1f 0);
  -webkit-mask:radial-gradient(#0000 63%, #000 64%); mask:radial-gradient(#0000 63%, #000 64%);
}
.donutCenter{
  position:absolute; top:50%; left:50%; transform:translate(-50%,-50%);
  display:flex; align-items:center; justify-content:center; width:70%; height:70%;
}
.donutCenter b{font-size:48px; line-height:1}
.donutPts{display:block; margin-top:8px; color:var(--muted); text-align:center}

.chart{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:16px;min-height:220px;display:grid;align-content:start;gap:10px}
.chart h2{margin:0 0 6px;font-size:16px;color:var(--muted);font-weight:600;letter-spacing:.25px}
.row{display:grid;grid-template-columns:110px 1fr 54px;align-items:center;gap:10px}
.k{color:var(--muted)}
.pbar{height:12px;background:#1e2129;border-radius:999px;position:relative;overflow:hidden}
.pbar>i{position:absolute;inset:0;width:0%;background:linear-gradient(90deg,#ef4444,#f97316,#facc15,#22c55e);transition:width .6s ease}

.desc{color:var(--muted);line-height:1.6;margin-top:20px}
.risk{margin:28px 0 16px}
.bar{height:16px;border-radius:999px;position:relative;background:linear-gradient(90deg,#e11d48,#f97316,#facc15,#22c55e)}
.bar .pin{position:absolute;top:50%;transform:translate(-50%,-50%);width:12px;height:12px;border-radius:50%;background:#fff;box-shadow:0 0 0 3px rgba(0,0,0,.35)}
.bubble{position:absolute;top:-34px;transform:translateX(-50%);background:#e5e7eb;color:#111827;border-radius:10px;padding:4px 8px;font-size:.85rem;white-space:nowrap}
.riskLabels{display:flex;justify-content:space-between;color:var(--muted);margin-top:6px;font-size:.95rem}

.recs{margin-top:28px}
.recs h2{font-size:22px;margin:0 0 10px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:14px}
.card h3{margin:0 0 8px;font-size:16px;color:var(--muted);font-weight:600;letter-spacing:.25px}
.card ol{margin:0;padding-left:18px}
.card li{margin:6px 0;line-height:1.35}
.card small{color:var(--muted)}
.pill{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:2px 8px;margin-left:6px;font-size:.75rem;color:var(--muted)}
</style></head>
<body><div class="wrap">
  <h1>{{TITLE}}</h1>
  <section class="top">
    <div class="donutBox">
      <div class="donut" id="donut">
        <div class="donutCenter"><b id="pctTxt">0%</b></div>
      </div>
      <small id="earnedTxt" class="donutPts">0/0</small>
      <small class="desc" style="margin-top:8px;text-align:center">Overall completion</small>
    </div>

    <div class="chart">
      <h2>Category completion (%)</h2>
      <div class="row"><div class="k">Identity</div><div class="pbar"><i id="barIdentity"></i></div><div id="pctIdentity">—%</div></div>
      <div class="row"><div class="k">Data</div><div class="pbar"><i id="barData"></i></div><div id="pctData">—%</div></div>
      <div class="row"><div class="k">Apps</div><div class="pbar"><i id="barApps"></i></div><div id="pctApps">—%</div></div>
      <div class="row"><div class="k">Devices</div><div class="pbar"><i id="barDevices"></i></div><div id="pctDevices">—%</div></div>
    </div>
  </section>

  <p class="desc" id="desc">{{DESC}}</p>

  <section class="risk">
    <div class="bar" id="riskBar" aria-label="Risk gradient">
      <div class="pin" id="pinYour"></div>
      <div class="bubble" id="bubbleYour">Your Business: <b id="yourVal">0%</b></div>
      <div class="pin" id="pinClient"></div>
      <div class="bubble" id="bubbleClient">Organizations of a similar size: <b id="clientVal">0%</b></div>
    </div>
    <div class="riskLabels"><span>High Risk</span><span>Low Risk</span></div>
  </section>

  <section class="recs">
    <h2>Top 3 “To be addressed” per category</h2>
    <div class="grid">
      <div class="card" id="cardIdentity"><h3>Identity</h3><ol></ol></div>
      <div class="card" id="cardData"><h3>Data</h3><ol></ol></div>
      <div class="card" id="cardApps"><h3>Apps</h3><ol></ol></div>
      <div class="card" id="cardDevices"><h3>Devices</h3><ol></ol></div>
    </div>
    <div id="recsNote" class="desc" style="display:none;margin-top:10px;"></div>
  </section>
</div>
<script id="scores" type="application/json">{{SCORES_JSON}}</script>
<script id="controls" type="application/json">{{CONTROLS_JSON}}</script>
<script>
(function(){
  const scores = JSON.parse(document.getElementById('scores').textContent || '{}');
  const controlsRaw = (function(){ try { return JSON.parse(document.getElementById('controls').textContent || 'null'); } catch(e){ return null; } })();

  // Donut (overall % guaranteed; keep a safety fallback here)
  const ov = scores.OverallScores || {};
  let pct = (typeof ov.PercentageScore==='number') ? ov.PercentageScore : null;
  let my  = (typeof ov.MyScore==='number') ? ov.MyScore : null;
  let max = (typeof ov.MaxScore==='number') ? ov.MaxScore : null;

  if ((pct==null || !isFinite(pct)) && (typeof my==='number') && (typeof max==='number') && max>0) {
    pct = (my/max)*100;
  }
  if (pct==null || !isFinite(pct)) pct = 0;
  if (my==null) my = 0;
  if (max==null) max = 0;

  const donut = document.getElementById('donut');
  donut.style.setProperty('--pct', Math.max(0, Math.min(100, pct)).toFixed(2));
  document.getElementById('pctTxt').textContent = Math.round(pct) + '%';
  document.getElementById('earnedTxt').textContent = `${my}/${max}`;

  // Risk bar markers — WITH % in bubbles
  const pinYour=document.getElementById('pinYour'), pinClient=document.getElementById('pinClient');
  const bubYour=document.getElementById('bubbleYour'), bubClient=document.getElementById('bubbleClient');
  const your=Math.max(0,Math.min(100,pct||0));
  const typical=(typeof ov.SimilarSeatsAverage==='number')?ov.SimilarSeatsAverage:((typeof ov.AllTenantAverage==='number')?ov.AllTenantAverage:null);
  function place(el,bubble,val){
    if(val==null){el.style.display='none';bubble.style.display='none';return;}
    el.style.left=val+'%';
    bubble.style.left=val+'%';
    bubble.querySelector('b').textContent = (Math.round(val*100)/100).toString() + '%';
  }
  place(pinYour,bubYour,your);
  place(pinClient,bubClient,typical);

  // Category percentages (avg of control %; fallback to score/max where possible)
  const mapped = Array.isArray(controlsRaw) ? controlsRaw.map(c=>{
    const title=c.title||'Untitled';
    const category=(c.category||'').toString().toLowerCase();
    const cur=(typeof c.current==='number')?c.current:null;
    const m=(typeof c.max==='number')?c.max:null;
    const perc=(typeof c.percentage==='number')?c.percentage:((cur!=null && m!=null && m>0)? (cur/m*100): null);
    const status=c.status||'';
    return {title,category,cur,max:m,percentage:perc,status};
  }) : [];

  const catMap={identity:['identity'],data:['data'],apps:['apps','application','app'],devices:['device','devices','endpoint']};
  function avgPct(cat){
    const buckets=catMap[cat];
    const arr=mapped.filter(x=>buckets.some(b=>x.category.includes(b))).map(x=>x.percentage).filter(v=>typeof v==='number' && isFinite(v));
    if (!arr.length) return null;
    return arr.reduce((a,b)=>a+b,0)/arr.length;
  }
  function applyBar(idSpan, idBar, val){
    const span=document.getElementById(idSpan);
    const bar=document.getElementById(idBar);
    if (val==null) { span.textContent='N/A'; bar.style.width='0%'; return; }
    const p=Math.max(0,Math.min(100,val));
    span.textContent=Math.round(p)+'%';
    bar.style.width=p.toFixed(2)+'%';
  }
  applyBar('pctIdentity','barIdentity', avgPct('identity'));
  applyBar('pctData','barData',         avgPct('data'));
  applyBar('pctApps','barApps',         avgPct('apps'));
  applyBar('pctDevices','barDevices',   avgPct('devices'));

  // Top-3 per category
  function pickTop3(cat){
    const buckets=catMap[cat];
    const known=mapped.filter(x=>buckets.some(b=>x.category.includes(b)) && x.cur!=null && x.max!=null && x.max>0);
    const unknown=mapped.filter(x=>buckets.some(b=>x.category.includes(b)) && !(x.cur!=null && x.max!=null && x.max>0));
    known.forEach(x=> x.pending = Math.max(0, x.max - x.cur));
    known.sort((a,b)=> (b.pending - a.pending) || (a.title||'').localeCompare(b.title||''));
    const res=known.slice(0,3);
    while(res.length<3 && unknown.length) res.push(unknown.shift());
    return res.slice(0,3);
  }
  function liLine(it){
    const chip = (it.cur!=null && it.max!=null && it.max>0) ? ` <span class="pill">${(it.max-it.cur).toFixed(2)} pts</span>` : '';
    const status = it.status ? ` <small>(${it.status})</small>` : '';
    return (it.title||'Untitled') + chip + status;
  }
  function fillCard(cardId, items){
    const ol=document.querySelector('#'+cardId+' ol'); ol.innerHTML='';
    if (!items || !items.length){ const li=document.createElement('li'); li.textContent='No data available.'; ol.appendChild(li); return; }
    items.forEach(it=>{ const li=document.createElement('li'); li.innerHTML=liLine(it); ol.appendChild(li); });
  }
  fillCard('cardIdentity', pickTop3('identity'));
  fillCard('cardData',     pickTop3('data'));
  fillCard('cardApps',     pickTop3('apps'));
  fillCard('cardDevices',  pickTop3('devices'));

  if (!mapped.length) {
    const note=document.getElementById('recsNote'); note.style.display='block';
    note.textContent='Note: no controlScores were found in your latest secureScores entry.';
  }
})();
</script></body></html>
'@

# ---------- Write ----------
$html = $template.Replace('{{TITLE}}', $Title).Replace('{{DESC}}', $Description)
$html = $html.Replace('{{SCORES_JSON}}', $scoresJson).Replace('{{CONTROLS_JSON}}', $controlsJson)
[IO.File]::WriteAllText($OutputHtmlPath, $html, [Text.Encoding]::UTF8)
Write-Host "Wrote: $OutputHtmlPath"
if ($Open) { Start-Process $OutputHtmlPath | Out-Null }
