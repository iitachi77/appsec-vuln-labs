<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LumosBlog</title>
  <style>
    :root{--bg:#0e1016;--panel:#171a24;--ink:#e8eaf2;--muted:#9aa0b5;--brand:#7c6cff;--line:#262a38}
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);
      font-family:Inter,Segoe UI,Roboto,Arial,sans-serif}
    .wrap{max-width:860px;margin:0 auto;padding:60px 22px}
    .brand{font-weight:800;font-size:22px;display:flex;align-items:center;gap:10px}
    .dot{width:14px;height:14px;border-radius:4px;background:linear-gradient(135deg,var(--brand),#5ad)}
    h1{font-size:40px;line-height:1.1;margin:34px 0 14px}
    p{color:var(--muted);font-size:17px;max-width:620px}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:28px}
    a{color:var(--brand)} .muted{color:var(--muted);font-size:13px}
    .post{padding:12px 0;border-bottom:1px solid var(--line)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="brand"><span class="dot"></span>LumosBlog</div>
    <h1>Where our team writes things down.</h1>
    <p>Product notes, launch posts, and the occasional engineering deep-dive. Built on Laravel.</p>

    @if(!empty($draft ?? null))
      <div class="card"><strong>Draft preview:</strong> {{ $draft }}</div>
    @endif

    <div class="card">
      <h3 style="margin-top:0">Latest posts</h3>
      <div class="post">Launch announcement — Q4 <span class="muted">· /preview/launch</span></div>
      <div class="post">Release notes v3.4 <span class="muted">· /preview/notes</span></div>
      <div class="post" style="border:none">Internal drafts are viewable at <code>/preview/&lt;slug&gt;</code></div>
    </div>

    <p class="muted" style="margin-top:26px">© LumosBlog. Staging build.</p>
  </div>
</body>
</html>
