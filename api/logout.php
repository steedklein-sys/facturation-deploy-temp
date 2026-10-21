<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';

$tok = current_token();
if ($tok) {
    $db = db_connect($cfg);
    ensure_schema($db);
    $hash = hash('sha256', $tok);
    $stmt = $db->prepare('DELETE FROM auth_tokens WHERE token_hash = ?');
    $stmt->bind_param('s', $hash);
    $stmt->execute();
}

setcookie('authtok', '', [
    'expires' => time() - 3600,
    'path' => '/',
]);

echo json_encode(['ok' => true]);
