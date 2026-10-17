<?php
require __DIR__ . '/db.php';
$page = $_GET['page'] ?? 'home';
$msg = '';
$err = '';

// ── Actions ──────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if ($page === 'register') {
        $u = trim($_POST['username'] ?? '');
        $p = $_POST['password'] ?? '';
        if ($u === '' || $p === '') {
            $err = 'Username and password are required.';
        } else {
            // SAFE: parameterised insert. Whatever you type is stored verbatim.
            try {
                $chk = $pdo->prepare("SELECT 1 FROM users WHERE username = ?");
                $chk->execute([$u]);
                if ($chk->fetch()) {
                    $err = 'That username is already taken.';
                } else {
                    $ins = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')");
                    $ins->execute([$u, $p]);
                    $msg = 'Account created. You can log in now.';
                }
            } catch (Exception $e) {
                $err = 'Registration failed.';
            }
        }
    }

    if ($page === 'login') {
        $u = trim($_POST['username'] ?? '');
        $p = $_POST['password'] ?? '';
        // SAFE: parameterised login.
        $s = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
        $s->execute([$u, $p]);
        $row = $s->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            $_SESSION['username'] = $row['username'];
            header('Location: ?page=dashboard');
            exit;
        }
        $err = 'Invalid credentials.';
    }

    if ($page === 'changepw') {
        $me = current_user($pdo);
        if (!$me) { header('Location: ?page=login'); exit; }
        $new = $_POST['new_password'] ?? '';
        // The NEW password is safely bound. But the username used to locate the
        // row is taken from the stored account and concatenated into the query.
        $sql = "UPDATE users SET password = :p WHERE username = '" . $me['username'] . "'";
        try {
            $st = $pdo->prepare($sql);
            $st->execute([':p' => $new]);
            $msg = 'Your password has been changed.';
        } catch (Exception $e) {
            $err = 'Could not change password.';
        }
    }

    if ($page === 'logout') {
        session_destroy();
        header('Location: ?page=home');
        exit;
    }
}

$me = current_user($pdo);
function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES); }
?>
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MemberZone</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:36px auto;padding:0 16px;background:#0f1216;color:#e8eef3}
a{color:#6cc7ff;text-decoration:none} a:hover{text-decoration:underline}
nav{display:flex;gap:14px;border-bottom:1px solid #263040;padding-bottom:12px;margin-bottom:20px;flex-wrap:wrap}
.card{background:#161b22;border:1px solid #263040;border-radius:10px;padding:20px;margin:14px 0}
input{display:block;width:100%;box-sizing:border-box;padding:9px;margin:7px 0 14px;background:#0d1117;border:1px solid #30363d;color:#e8eef3;border-radius:6px}
button{background:#1f6feb;color:#fff;border:0;padding:10px 18px;border-radius:6px;cursor:pointer;font-size:15px}
.msg{background:#122a17;border:1px solid #1f6f3a;padding:10px 14px;border-radius:8px;margin:10px 0}
.err{background:#2a1316;border:1px solid #6f1f26;padding:10px 14px;border-radius:8px;margin:10px 0}
.flag{background:#2a2410;border:1px solid #6f5c1f;padding:14px;border-radius:8px;font-size:17px}
code{background:#0d1117;padding:2px 6px;border-radius:4px;border:1px solid #30363d}
h1{margin:0 0 4px} .muted{color:#8b98a5;font-size:14px}
</style></head><body>

<nav>
  <a href="?page=home"><b>🏷️ MemberZone</b></a>
  <?php if ($me): ?>
    <a href="?page=dashboard">Dashboard</a>
    <a href="?page=changepw">Change password</a>
    <span class="muted">· <?=h($me['username'])?></span>
    <form action="?page=logout" method="post" style="margin:0"><button style="background:#30363d;padding:4px 10px;font-size:13px">Logout</button></form>
  <?php else: ?>
    <a href="?page=login">Login</a>
    <a href="?page=register">Register</a>
  <?php endif; ?>
</nav>

<?php if ($msg): ?><div class="msg"><?=h($msg)?></div><?php endif; ?>
<?php if ($err): ?><div class="err"><?=h($err)?></div><?php endif; ?>

<?php if ($page === 'home'): ?>
  <h1>🏷️ MemberZone</h1>
  <p class="muted">A tiny membership portal.</p>
  <div class="card">
    <b>Objective:</b> there is an <code>admin</code> account holding a <code>FLAG{...}</code> on its
    dashboard. Its password is random — you cannot guess or brute-force it. Take over the admin
    account anyway, and read the flag.
    <p class="muted">Tip: register, log in, and look closely at how the app handles your account. Not every
    query in this app is as safe as it first appears.</p>
  </div>

<?php elseif ($page === 'register'): ?>
  <div class="card"><h2>Register</h2>
    <form method="post" action="?page=register">
      <label>Username</label><input name="username" autofocus>
      <label>Password</label><input name="password" type="password">
      <button>Create account</button>
    </form>
  </div>

<?php elseif ($page === 'login'): ?>
  <div class="card"><h2>Login</h2>
    <form method="post" action="?page=login">
      <label>Username</label><input name="username" autofocus>
      <label>Password</label><input name="password" type="password">
      <button>Sign in</button>
    </form>
  </div>

<?php elseif ($page === 'dashboard'): ?>
  <?php if (!$me) { header('Location: ?page=login'); exit; } ?>
  <div class="card">
    <h2>Welcome, <?=h($me['username'])?></h2>
    <p class="muted">Role: <?=h($me['role'])?></p>
    <?php if ($me['role'] === 'admin'): ?>
      <div class="flag">🚩 <?=h($me['note'])?></div>
    <?php else: ?>
      <p>Nothing to see here — regular members don't get secrets. 🙂</p>
    <?php endif; ?>
  </div>

<?php elseif ($page === 'changepw'): ?>
  <?php if (!$me) { header('Location: ?page=login'); exit; } ?>
  <div class="card"><h2>Change password</h2>
    <form method="post" action="?page=changepw">
      <label>New password</label><input name="new_password" type="password" autofocus>
      <button>Update password</button>
    </form>
    <p class="muted">Changes the password for your account: <code><?=h($me['username'])?></code></p>
  </div>

<?php endif; ?>

</body></html>
