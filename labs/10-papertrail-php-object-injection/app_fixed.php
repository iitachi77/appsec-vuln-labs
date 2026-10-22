<?php
// PaperTrail — PATCHED.  Prototype of the secure preferences flow.
//
// ROOT CAUSE of the original bug: unserialize() on attacker-controlled bytes instantiates
// arbitrary objects, whose magic methods (__wakeup/__destruct) then run — PHP object injection.
//
// FIX: never unserialize untrusted input. Preferences are plain key/value data, so persist them
// as JSON (which can only ever produce arrays/scalars — never an object with code paths), and sign
// the cookie with an HMAC so it can't be tampered with in the first place (defense in depth).

error_reporting(0);

define('COOKIE_SECRET', getenv('PREFS_SECRET') ?: bin2hex(random_bytes(32)));
const ALLOWED = [
    'theme'   => ['light', 'dark', 'sepia'],
    'density' => ['cozy', 'compact'],
];

function sign(string $payload): string {
    return hash_hmac('sha256', $payload, COOKIE_SECRET);
}

function load_prefs(): array {
    $default = ['theme' => 'light', 'density' => 'cozy'];
    if (empty($_COOKIE['prefs'])) return $default;

    // cookie format:  base64(json).hmac   — verify the signature before trusting anything
    $parts = explode('.', $_COOKIE['prefs'], 2);
    if (count($parts) !== 2) return $default;
    [$b64, $mac] = $parts;
    if (!hash_equals(sign($b64), $mac)) return $default;          // tampered -> ignore

    // JSON only — can never instantiate an object (no object injection possible)
    $data = json_decode(base64_decode($b64), true);
    if (!is_array($data)) return $default;

    // allow-list: only known keys with known values survive
    $prefs = $default;
    foreach (ALLOWED as $key => $values) {
        if (isset($data[$key]) && in_array($data[$key], $values, true)) {
            $prefs[$key] = $data[$key];
        }
    }
    return $prefs;
}

function save_prefs(array $prefs): void {
    $b64 = base64_encode(json_encode($prefs));
    setcookie('prefs', $b64 . '.' . sign($b64), time() + 86400, '/');
}

$prefs = load_prefs();
if (empty($_COOKIE['prefs'])) save_prefs($prefs);

$theme = htmlspecialchars($prefs['theme']);
echo "<h1>PaperTrail</h1><p>Internal reporting dashboard. Theme: <b>$theme</b>.</p>";
echo "<p>Preferences are stored as a <em>signed JSON</em> cookie and restored safely on every visit.</p>";
