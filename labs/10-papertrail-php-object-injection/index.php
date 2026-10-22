<?php
// PaperTrail — internal reporting dashboard.  Educational lab only.
// Looks like a normal product; underneath is a PHP OBJECT INJECTION flaw:
// user preferences are restored from a cookie with unserialize() on attacker data.
// This is the same vulnerability FAMILY as the PHP2Shell session-unserializer CVE.

error_reporting(0);

// ---------------------------------------------------------------------------
// A legitimate helper used by the "Export report" feature: on cleanup it writes
// the buffered report to disk. Perfectly normal in isolation...
// ...but it's a GADGET: its __destruct() runs for ANY object of this class that
// gets created — including one an attacker smuggles in via unserialize().
class ReportExporter {
    public $path = null;    // where the export is written
    public $data = "";      // the export contents
    public function __destruct() {
        if ($this->path) {
            file_put_contents($this->path, $this->data);   // attacker-controlled path + data = file write / webshell
        }
    }
}

// ---------------------------------------------------------------------------
// Restore the visitor's preferences from their cookie.
$prefs = ["theme" => "light", "density" => "cozy"];

if (isset($_COOKIE["prefs"])) {
    // VULNERABLE: unserialize() on fully attacker-controlled bytes -> PHP object injection.
    // Even though we only "use" the result when it's an array, merely unserializing an
    // object INSTANTIATES it, and its __destruct() fires when the script ends.
    $restored = unserialize(base64_decode($_COOKIE["prefs"]));
    if (is_array($restored)) {
        $prefs = array_merge($prefs, $restored);
    }
} else {
    // seed a normal prefs cookie so the app "just works"
    setcookie("prefs", base64_encode(serialize($prefs)), time() + 86400, "/");
}

$theme   = htmlspecialchars($prefs["theme"] ?? "light");
$density = htmlspecialchars($prefs["density"] ?? "cozy");
?>
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PaperTrail</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1f2933;--mut:#66727e;--line:#e6e9ee;--acc:#2f6fed;--acc2:#eaf1ff}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--ink)}
.top{display:flex;align-items:center;justify-content:space-between;padding:13px 26px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand{font-weight:700;font-size:18px;display:flex;align-items:center;gap:9px}
.brand .d{width:22px;height:22px;border-radius:6px;background:var(--acc);display:inline-block}
.who{font-size:13px;color:var(--mut)}
.wrap{max-width:1000px;margin:0 auto;padding:24px 26px}
.row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:18px}
@media(max-width:800px){.row{grid-template-columns:1fr}}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
.kpi b{font-size:26px;display:block;letter-spacing:-.5px}.kpi span{color:var(--mut);font-size:12.5px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
.panel h2{font-size:15px;margin:0 0 4px}.panel p{color:var(--mut);font-size:13px;margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.pill{font-size:12px;padding:2px 9px;border-radius:999px;background:var(--acc2);color:var(--acc)}
.meta{margin-top:14px;color:var(--mut);font-size:12px}
.meta code{background:#f0f2f5;padding:1px 6px;border-radius:5px}
</style></head>
<body data-theme="<?php echo $theme; ?>" data-density="<?php echo $density; ?>">
<div class="top">
  <div class="brand"><span class="d"></span> PaperTrail</div>
  <div class="who">Signed in as <b>analyst</b> · theme: <?php echo $theme; ?></div>
</div>
<div class="wrap">
  <div class="row">
    <div class="kpi"><b>$482,900</b><span>Revenue (Q3)</span></div>
    <div class="kpi"><b>1,204</b><span>Reports generated</span></div>
    <div class="kpi"><b>99.9%</b><span>Export success rate</span></div>
  </div>
  <div class="panel">
    <h2>Recent reports</h2>
    <p>Your latest generated exports.</p>
    <table>
      <tr><th>Report</th><th>Owner</th><th>Status</th></tr>
      <tr><td>Q3 Revenue Summary</td><td>analyst</td><td><span class="pill">exported</span></td></tr>
      <tr><td>Churn Analysis</td><td>maria</td><td><span class="pill">exported</span></td></tr>
      <tr><td>Pipeline Forecast</td><td>analyst</td><td><span class="pill">exported</span></td></tr>
    </table>
    <div class="meta">Preferences are remembered in your <code>prefs</code> session cookie and restored on every visit.</div>
  </div>
</div>
</body></html>
