<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/webauthn.php';

$db = db_connect($cfg);
ensure_schema($db);

wa_session_start();
$challenge = random_bytes(32);
$_SESSION['wa_challenge'] = base64_encode($challenge);
$_SESSION['wa_challenge_type'] = 'get';

$res = $db->query('SELECT credential_id FROM webauthn_credentials');
$allow = [];
while ($res && ($row = $res->fetch_assoc())) {
    $allow[] = ['type' => 'public-key', 'id' => b64u_encode((string)$row['credential_id'])];
}

if (!$allow) {
    http_response_code(404);
    echo json_encode(['ok' => false, 'error' => 'aucune empreinte enregistrée']);
    exit;
}

echo json_encode([
    'challenge' => b64u_encode($challenge),
    'rpId' => WA_RP_ID,
    'allowCredentials' => $allow,
    'userVerification' => 'required',
    'timeout' => 60000,
]);
