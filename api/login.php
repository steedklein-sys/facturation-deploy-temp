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
create_session($db);

echo json_encode(['ok' => true]);
