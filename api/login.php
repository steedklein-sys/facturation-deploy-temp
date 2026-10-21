<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'méthode non supportée']);
    exit;
}

$body = json_decode((string)file_get_contents('php://input'), true);
$pass = is_array($body) ? ($body['password'] ?? '') : '';

if (!is_string($pass) || $pass === '' || !password_verify($pass, $cfg['app_password_hash'])) {
    usleep(400000); // ralentit les essais automatisés
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'Mot de passe incorrect']);
    exit;
}

$db = db_connect($cfg);
ensure_schema($db);

$token = bin2hex(random_bytes(32));
$hash = hash('sha256', $token);
$stmt = $db->prepare('INSERT INTO auth_tokens (token_hash, created_at, last_used_at) VALUES (?, NOW(), NOW())');
$stmt->bind_param('s', $hash);
$stmt->execute();

$secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
setcookie('authtok', $token, [
    'expires' => time() + 60 * 60 * 24 * 365,
    'path' => '/',
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Lax',
]);

echo json_encode(['ok' => true]);
