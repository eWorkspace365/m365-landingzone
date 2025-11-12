param(
  [Parameter(Mandatory = $true)]
  [string]$InputJson,                                   # Path to the source JSON file
  [string]$OutputHtml = "$(Split-Path -LeafBase $InputJson)-dashboard.html",
  [string]$Title = "CIS Microsoft 365 Foundations Benchmark v5.0.0"
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $InputJson)) {
  throw "Input JSON not found: $InputJson"
}

# Read JSON (expect an array of objects)
$raw = Get-Content -Raw -Encoding UTF8 -Path $InputJson | ConvertFrom-Json
if ($raw -isnot [System.Collections.IEnumerable] -or $raw -is [string]) { $raw = @($raw) }

# Map fields and normalize "Implementation Group" to an array
$data = foreach ($row in $raw) {
  $control  = $row.'Control';  if (-not $control)  { $control  = $row.'control' }
  $profile  = $row.'Profile';  if (-not $profile)  { $profile  = $row.'profile' }
  $summary  = $row.'Summary';  if (-not $summary)  { $summary  = $row.'summary' }
  $category = $row.'Category'; if (-not $category) { $category = $row.'category' }
  $status   = $row.'Status';   if (-not $status)   { $status   = $row.'status' }
  $impl     = $row.'Implementation Group'
  if (-not $impl) { $impl = $row.'implementation group' }
  if (-not $impl) { $impl = $row.'implementation_group' }

  if ($null -eq $impl) {
    $impl = @()
  }
  elseif ($impl -isnot [System.Collections.IEnumerable] -or $impl -is [string]) {
    $impl = @($impl) | Where-Object { $_ -ne $null -and $_ -ne "" }
  }

  [ordered]@{
    "Control"              = "$control"
    "Profile"              = "$profile"
    "Summary"              = "$summary"
    "Category"             = "$category"
    "Status"               = "$status"
    "Implementation Group" = $impl
  }
}

$dataJson  = $data | ConvertTo-Json -Depth 50 -Compress
$generated = (Get-Date).ToString("yyyy-MM-dd HH:mm")
$count     = @($data).Count

# Use single-quoted here-string and token replacement to avoid parser issues
$template = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
  :root {
    --bg: #f5f7fb;
    --panel: #ffffff;
    --text: #0f172a;
    --subtext: #475569;
    --muted: #64748b;
    --border: #e2e8f0;
    --border-strong: #cbd5e1;
    --accent: #3b82f6;
    --accent-2: #06b6d4;
    --good: #16a34a;
    --warn: #d97706;
    --bad:  #dc2626;
    --chip-bg: #eff6ff;
    --chip-border: #dbeafe;
    --chip-text: #1e40af;
    --radius: 14px;
    --shadow: 0 10px 24px rgba(15, 23, 42, 0.06);
    --shadow-weak: 0 1px 2px rgba(15, 23, 42, 0.06);
  }
  * { box-sizing: border-box; }
  html, body {
    margin:0; padding:0; background: var(--bg);
    color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
  }
  header.hero {
    position: sticky; top: 0; z-index: 40;
    background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
    border-bottom: 1px solid var(--border);
  }
  .wrap { max-width: 1280px; margin: 0 auto; padding: 16px 20px; }
  .title-row { display:flex; align-items:center; gap:14px; }
  .logo {
    width: 42px; height: 42px; border-radius: 10px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    display:grid; place-items:center; box-shadow: var(--shadow);
    color:white;
  }
  .logo svg { width:24px; height:24px; }
  h1 { margin:0; font-size: clamp(20px, 3vw, 26px); font-weight: 750; letter-spacing: 0.2px; }
  .subtitle { color: var(--subtext); font-size: 12px; margin-top: 2px; }
  .toolbar {
    margin-top: 14px;
    display:grid; grid-template-columns: 1fr auto auto; gap:10px; align-items:center;
  }
  .stat {
    display:flex; align-items:center; gap:8px;
    background: var(--panel); border:1px solid var(--border);
    padding: 8px 12px; border-radius: 999px; box-shadow: var(--shadow-weak);
    color: var(--subtext);
  }
  .btn {
    cursor:pointer; font-weight:600;
    border-radius: 10px; padding:10px 14px;
    border:1px solid var(--border-strong);
    background: var(--panel); color: var(--text);
    transition: transform .05s ease-in-out, border-color .15s, box-shadow .15s, background .15s;
    box-shadow: var(--shadow-weak);
  }
  .btn:hover { border-color: var(--accent); }
  .btn:active { transform: translateY(1px); }
  .btn.primary { background: var(--accent); color: white; border-color: var(--accent); }
  .btn.primary:hover { filter: brightness(0.98); }

  .field, select, input[type="search"] {
    width:100%;
    border-radius: 10px;
    border: 1px solid var(--border-strong);
    padding: 12px 14px;
    background: #ffffff;
    color: var(--text);
    outline: none;
    box-shadow: var(--shadow-weak);
  }
  input::placeholder { color: #94a3b8; }

  select {
    appearance: none; -webkit-appearance: none; -moz-appearance: none;
    background-image:
      url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 20 20' fill='none' stroke='%23566' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polyline points='6 8 10 12 14 8'/></svg>");
    background-repeat: no-repeat;
    background-position: right 12px center;
    background-size: 20px 20px;
    padding-right: 40px;
  }
  select:focus, input[type="search"]:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(59,130,246,0.18);
  }

  main { max-width: 1280px; margin: 18px auto 60px; padding: 0 20px; }

  .card { background: var(--panel); border:1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); }
  .pad { padding: 14px; }

  .summary-row { display:flex; gap:10px; align-items:center; margin: 16px 0; }
  .summary-row label { min-width: 150px; color: var(--subtext); font-size: 13px; }

  .filters-grid { display: grid; gap: 12px; grid-template-columns: repeat(5, minmax(0, 1fr)); }
  .filter-group label { display:block; font-size: 12px; color: var(--subtext); margin-bottom: 6px; }
  .filter-group select { width:100%; }

  .table-wrap { margin-top: 14px; overflow: clip; border-top-left-radius: var(--radius); border-top-right-radius: var(--radius); }
  table { width:100%; border-collapse: collapse; }
  thead th {
    position: sticky; top: 0; z-index: 10;
    background: #f8fafc; color:#0f172a;
    border-bottom: 1px solid var(--border);
    text-align:left; font-weight:700; font-size: 13px; padding: 12px; cursor: pointer; user-select:none;
  }
  tbody td {
    font-size: 14px; padding: 12px; border-bottom: 1px solid var(--border);
    vertical-align: top; color: #111827;
  }
  tbody tr:nth-child(odd) { background: #fbfdff; }
  tbody tr:hover { background: #f1f5f9; }
  .sort-ind { font-size:11px; color:#334155; margin-left:6px; }
  .chips { display:flex; gap:6px; flex-wrap: wrap; }
  .chip { background: var(--chip-bg); color: var(--chip-text); border:1px solid var(--chip-border); padding: 3px 8px; border-radius: 999px; font-size: 12px; }

  .status.Open { color: var(--warn); font-weight:700; }
  .status.Compliant { color: var(--good); font-weight:700; }

  .pagination { display:flex; gap:8px; justify-content:flex-end; align-items:center; padding: 10px; border-top: 1px solid var(--border); }
  .pagination .btn { padding: 8px 12px; }
  .page-size { width:auto; }

  @media (max-width: 1100px) { .filters-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
</head>
<body>
<header class="hero">
  <div class="wrap">
    <div class="title-row">
      <div class="logo" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 3v18M3 12h18" stroke-linecap="round"/>
        </svg>
      </div>
      <div>
        <h1>{{TITLE}}</h1>
        <div class="subtitle">Generated {{GENERATED}}</div>
      </div>
    </div>
    <div class="toolbar">
      <div class="stat" title="Rows currently shown">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M3 12h18M3 18h18"/></svg>
        <span id="shownCount">0</span>/<span id="totalCount">{{COUNT}}</span>
      </div>
      <button id="clear" class="btn" title="Clear all filters">Clear filters</button>
      <button id="exportCsv" class="btn primary" title="Export current view to CSV">Export CSV</button>
    </div>
  </div>
</header>

<main>
  <div class="card">
    <div class="pad">
      <div class="summary-row">
        <label for="summaryQ">Search in Summary</label>
        <input id="summaryQ" class="field" type="search" placeholder="Type keywords to filter the Summary column only">
      </div>
      <div class="filters-grid" id="filtersGrid"></div>
    </div>

    <div class="table-wrap">
      <table id="dataTable">
        <thead>
          <tr>
            <th data-col='Control'>Control <span class='sort-ind'></span></th>
            <th data-col='Profile'>Profile <span class='sort-ind'></span></th>
            <th data-col='Summary'>Summary <span class='sort-ind'></span></th>
            <th data-col='Category'>Category <span class='sort-ind'></span></th>
            <th data-col='Status'>Status <span class='sort-ind'></span></th>
            <th data-col='Implementation Group'>Implementation Group <span class='sort-ind'></span></th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
      <div class="pagination">
        <button id="prevPage" class="btn">Prev</button>
        <span id="pageInfo" class="subtitle">Page 1</span>
        <button id="nextPage" class="btn">Next</button>
        <select id="pageSize" class="field page-size" title="Rows per page">
          <option>10</option>
          <option selected>25</option>
          <option>50</option>
          <option>100</option>
        </select>
      </div>
    </div>
  </div>
</main>

<script>
const RAW = {{DATA}};
const COLUMNS = ["Control","Profile","Summary","Category","Status","Implementation Group"];

function uniqueValues(field) {
  const set = new Set();
  for (const r of RAW) {
    const v = r[field];
    if (Array.isArray(v)) {
      for (const a of v) set.add(a);
    } else if (v !== undefined && v !== null) {
      set.add(v);
    }
  }
  return Array.from(set).sort((a,b)=>a.toString().localeCompare(b.toString(), undefined, {numeric:true}));
}

const DROPDOWN_COLS = ["Control","Profile","Category","Status","Implementation Group"];
const FILTERS = Object.fromEntries(DROPDOWN_COLS.map(c => [c, null])); // null = All

function renderFilters() {
  const grid = document.getElementById("filtersGrid");
  grid.innerHTML = "";
  for (const col of DROPDOWN_COLS) {
    const div = document.createElement("div");
    div.className = "filter-group";
    const label = document.createElement("label");
    label.textContent = col;
    const sel = document.createElement("select");
    sel.className = "field";
    const values = uniqueValues(col);
    sel.appendChild(Object.assign(document.createElement("option"), {value: "", textContent: "All"}));
    for (const v of values) {
      const o = document.createElement("option");
      o.value = v; o.textContent = v;
      if (FILTERS[col] === v) o.selected = true;
      sel.appendChild(o);
    }
    sel.addEventListener("change", () => { FILTERS[col] = sel.value || null; update(); });
    div.appendChild(label);
    div.appendChild(sel);
    grid.appendChild(div);
  }
}

let sortOrder = [["Control", 1]]; // Default sort by Control asc
function compareRows(a, b) {
  for (const [col, dir] of sortOrder) {
    const sa = Array.isArray(a[col]) ? a[col].join(", ") : (a[col] ?? "");
    const sb = Array.isArray(b[col]) ? b[col].join(", ") : (b[col] ?? "");
    const cmp = sa.toString().localeCompare(sb.toString(), undefined, {numeric:true, sensitivity:"base"});
    if (cmp !== 0) return cmp * dir;
  }
  return 0;
}

let currentPage = 1;
let pageSize = 25;

function applyFilters() {
  const q = document.getElementById("summaryQ").value.trim().toLowerCase();
  return RAW.filter(row => {
    const sum = (row["Summary"] ?? "").toString().toLowerCase();
    if (q && !sum.includes(q)) return false;

    for (const col of DROPDOWN_COLS) {
      const sel = FILTERS[col];
      if (sel === null) continue;
      const val = row[col];
      if (col === "Implementation Group") {
        const arr = Array.isArray(val) ? val : (val ? [val] : []);
        if (!arr.includes(sel)) return false;
      } else {
        if (val !== sel) return false;
      }
    }
    return true;
  });
}

function renderTable(rows) {
  const tbody = document.querySelector("#dataTable tbody");
  tbody.innerHTML = "";
  const start = (currentPage - 1) * pageSize;
  const end = Math.min(start + pageSize, rows.length);
  for (let i = start; i < end; i++) {
    const r = rows[i];
    const tr = document.createElement("tr");
    for (const col of COLUMNS) {
      const td = document.createElement("td");
      const v = r[col];
      if (Array.isArray(v)) {
        const wrap = document.createElement("div");
        wrap.className = "chips";
        v.forEach(ch => { const s = document.createElement("span"); s.className="chip"; s.textContent = ch; wrap.appendChild(s); });
        td.appendChild(wrap);
      } else {
        if (col === "Status") {
          const span = document.createElement("span");
          span.className = 'status ' + ((v ?? '').toString());
          span.textContent = v ?? "";
          td.appendChild(span);
        } else {
          td.textContent = (v ?? "").toString();
        }
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  document.getElementById("shownCount").textContent = rows.length;
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  currentPage = Math.min(currentPage, totalPages);
  document.getElementById("pageInfo").textContent = "Page " + currentPage + " / " + totalPages;
  document.getElementById("prevPage").disabled = currentPage <= 1;
  document.getElementById("nextPage").disabled = currentPage >= totalPages;
}

function update() {
  let rows = applyFilters();
  rows.sort(compareRows);
  renderTable(rows);
}

function resetFilters() {
  document.getElementById("summaryQ").value = "";
  for (const col of DROPDOWN_COLS) FILTERS[col] = null;
  currentPage = 1;
  renderFilters();
  update();
}

function initSorting() {
  const headers = document.querySelectorAll("thead th");
  headers.forEach(th => {
    th.addEventListener("click", (e) => {
      const col = th.dataset.col;
      const withShift = e.shiftKey;
      const idx = sortOrder.findIndex(s => s[0] === col);
      if (!withShift) sortOrder = [];
      if (idx === -1) sortOrder.push([col, 1]);
      else {
        const d = sortOrder[idx][1];
        if (d === 1) sortOrder[idx][1] = -1; else sortOrder.splice(idx, 1);
      }
      document.querySelectorAll(".sort-ind").forEach(s => s.textContent = "");
      sortOrder.forEach(([c, d]) => {
        const h = document.querySelector('thead th[data-col="' + c + '"] .sort-ind');
        if (h) h.textContent = d === 1 ? "▲" : "▼";
      });
      update();
    });
  });
}

function exportCSV() {
  let rows = applyFilters().sort(compareRows);
  const header = COLUMNS.join(",");
  const csvRows = rows.map(r => COLUMNS.map(c => {
    let v = r[c];
    if (Array.isArray(v)) v = v.join("; ");
    v = (v ?? "").toString().replaceAll('"','""');
    if (/[",\n]/.test(v)) v = '"' + v + '"';
    return v;
  }).join(","));
  const csv = [header, ...csvRows].join("\n");
  const blob = new Blob([csv], {type: "text/csv;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "cis-view-clean.csv";
  a.click();
  URL.revokeObjectURL(url);
}

document.addEventListener("DOMContentLoaded", () => {
  renderFilters();
  initSorting();
  const ctrlHead = document.querySelector('thead th[data-col="Control"] .sort-ind');
  if (ctrlHead) ctrlHead.textContent = "";
  update();

  document.getElementById("summaryQ").addEventListener("input", () => { currentPage = 1; update(); });
  document.getElementById("clear").addEventListener("click", resetFilters);
  document.getElementById("prevPage").addEventListener("click", () => { if (currentPage>1) { currentPage--; update(); } });
  document.getElementById("nextPage").addEventListener("click", () => { currentPage++; update(); });
  document.getElementById("pageSize").addEventListener("change", (e) => { pageSize = parseInt(e.target.value,10); currentPage = 1; update(); });
  document.getElementById("exportCsv").addEventListener("click", exportCSV);
});
</script>
</body>
</html>
'@

# Inject runtime values safely
$html = $template.
  Replace('{{TITLE}}',     $Title).
  Replace('{{GENERATED}}', $generated).
  Replace('{{COUNT}}',     "$count").
  Replace('{{DATA}}',      $dataJson)

# Write the file (UTF-8)
Set-Content -Path $OutputHtml -Value $html -Encoding UTF8
Write-Host "Dashboard written to: $OutputHtml"
