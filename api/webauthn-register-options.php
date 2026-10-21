<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/webauthn.php';

$db = db_connect($cfg);
ensure_schema($db);
require_auth($db); // il faut déjà être connecté (par mot de passe) pour activer l'empreinte

wa_session_start();
$challenge = random_bytes(32);
$_SESSION['wa_challenge'] = base64_encode($challenge);
$_SESSION['wa_challenge_type'] = 'create';

// Identifiant WebAuthn fixe : application mono-utilisateur, un seul "compte".
$userId = hash('sha256', 'steed-facturation', true);

echo json_encode([
    'challenge' => b64u_encode($challenge),
    'rp' => ['name' => 'Facturation STEED', 'id' => WA_RP_ID],
    'user' => [
        'id' => b64u_encode($userId),
        'name' => 'steed',
        'displayName' => 'STEED Solutions Extérieures',
    ],
    'pubKeyCredParams' => [['type' => 'public-key', 'alg' => -7]], // ES256
    'authenticatorSelection' => [
        'authenticatorAttachment' => 'platform',
        'userVerification' => 'required',
        'residentKey' => 'preferred',
    ],
    'timeout' => 60000,
    'attestation' => 'none',
]);
