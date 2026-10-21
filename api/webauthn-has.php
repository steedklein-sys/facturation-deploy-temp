<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';

$db = db_connect($cfg);
ensure_schema($db);

$res = $db->query('SELECT COUNT(*) AS n FROM webauthn_credentials');
$row = $res ? $res->fetch_assoc() : ['n' => 0];

echo json_encode(['available' => ((int)($row['n'] ?? 0)) > 0]);
