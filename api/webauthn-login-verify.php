<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/webauthn.php';

$db = db_connect($cfg);
ensure_schema($db);

wa_session_start();
$expected = isset($_SESSION['wa_challenge']) ? base64_decode($_SESSION['wa_challenge']) : null;
if (!$expected || ($_SESSION['wa_challenge_type'] ?? '') !== 'get') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'session expirée, réessayez']);
    exit;
}

$body = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($body)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'requête invalide']);
    exit;
}

$rawId = b64u_decode((string)($body['id'] ?? ''));
$clientDataJSON = b64u_decode((string)($body['clientDataJSON'] ?? ''));
$authenticatorData = b64u_decode((string)($body['authenticatorData'] ?? ''));
$signature = b64u_decode((string)($body['signature'] ?? ''));

$clientData = json_decode($clientDataJSON, true);
if (!is_array($clientData) || ($clientData['type'] ?? '') !== 'webauthn.get') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'type invalide']);
    exit;
}
if (b64u_decode((string)($clientData['challenge'] ?? '')) !== $expected) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'challenge invalide']);
    exit;
}
if (($clientData['origin'] ?? '') !== WA_ORIGIN) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'origine invalide']);
    exit;
}

$stmt = $db->prepare('SELECT credential_id, public_key_pem, sign_count FROM webauthn_credentials WHERE credential_id = ? LIMIT 1');
$stmt->bind_param('s', $rawId);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
if (!$row) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'empreinte inconnue']);
    exit;
}

$expectedRpIdHash = hash('sha256', WA_RP_ID, true);
$rpIdHash = substr($authenticatorData, 0, 32);
$flags = ord($authenticatorData[32] ?? "\x00");
$signCountArr = unpack('N', substr($authenticatorData, 33, 4));
$signCount = $signCountArr ? $signCountArr[1] : 0;

if ($rpIdHash !== $expectedRpIdHash) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'rpId invalide']);
    exit;
}
if (!($flags & 0x01)) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'présence utilisateur manquante']);
    exit;
}

$pubKey = openssl_pkey_get_public($row['public_key_pem']);
if (!$pubKey) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'clé invalide']);
    exit;
}

$signedData = $authenticatorData . hash('sha256', $clientDataJSON, true);
$verified = openssl_verify($signedData, $signature, $pubKey, OPENSSL_ALGO_SHA256);
if ($verified !== 1) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'signature invalide']);
    exit;
}

$storedCount = (int)$row['sign_count'];
if ($signCount !== 0 && $storedCount !== 0 && $signCount <= $storedCount) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'compteur de sécurité invalide']);
    exit;
}

$upd = $db->prepare('UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?');
$upd->bind_param('is', $signCount, $rawId);
$upd->execute();

unset($_SESSION['wa_challenge'], $_SESSION['wa_challenge_type']);

create_session($db);
echo json_encode(['ok' => true]);
