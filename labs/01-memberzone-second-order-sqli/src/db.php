<?php
// ── MemberZone bootstrap ─────────────────────────────────────────────────────
// Educational lab only.
session_start();
$DB = '/tmp/memberzone.db';
$fresh = !file_exists($DB);
$pdo = new PDO('sqlite:' . $DB);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

if ($fresh) {
    $pdo->exec("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        note TEXT
    )");
    // The admin password is randomised, so it cannot be guessed or brute-forced.
    $admPw = 'Adm1n_' . bin2hex(random_bytes(6));
    $s = $pdo->prepare("INSERT INTO users (username, password, role, note) VALUES (?, ?, ?, ?)");
    $s->execute(['admin', $admPw, 'admin', 'FLAG{s3c0nd_0rd3r_sqli_st0r3d_th3n_str1k3s}']);
}

function current_user($pdo) {
    if (empty($_SESSION['username'])) return null;
    $s = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $s->execute([$_SESSION['username']]);
    return $s->fetch(PDO::FETCH_ASSOC);
}
