<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/webauthn.php';

$db = db_connect($cfg);
ensure_schema($db);
require_auth($db);

wa_session_start();
$expected = isset($_SESSION['wa_challenge']) ? base64_decode($_SESSION['wa_challenge']) : null;
if (!$expected || ($_SESSION['wa_challenge_type'] ?? '') !== 'create') {
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

$clientDataJSON = b64u_decode((string)($body['clientDataJSON'] ?? ''));
$attestationObject = b64u_decode((string)($body['attestationObject'] ?? ''));
$label = is_string($body['label'] ?? null) ? substr((string)$body['label'], 0, 100) : '';

$clientData = json_decode($clientDataJSON, true);
if (!is_array($clientData) || ($clientData['type'] ?? '') !== 'webauthn.create') {
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

$off = 0;
$att = cbor_decode($attestationObject, $off);
$authData = is_array($att) ? ($att['authData'] ?? null) : null;
if (!is_string($authData)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'données invalides']);
    exit;
}

$parsed = parse_auth_data($authData);
$expectedRpIdHash = hash('sha256', WA_RP_ID, true);
if ($parsed['rpIdHash'] !== $expectedRpIdHash) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'rpId invalide']);
    exit;
}
if (!($parsed['flags'] & 0x01)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'présence utilisateur manquante']);
    exit;
}
if (!$parsed['credentialId'] || !is_array($parsed['cosePublicKey'])) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'clé manquante']);
    exit;
}

$pem = cose_ec2_to_pem($parsed['cosePublicKey']);
if (!$pem) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'type de clé non pris en charge']);
    exit;
}

$credId = $parsed['credentialId'];
$signCount = (int)$parsed['signCount'];
$stmt = $db->prepare('INSERT INTO webauthn_credentials (credential_id, public_key_pem, sign_count, label, created_at) VALUES (?, ?, ?, ?, NOW())');
$stmt->bind_param('ssis', $credId, $pem, $signCount, $label);
if (!$stmt->execute()) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'enregistrement impossible']);
    exit;
}

unset($_SESSION['wa_challenge'], $_SESSION['wa_challenge_type']);
echo json_encode(['ok' => true]);
