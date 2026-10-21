<?php
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

$cfg = require __DIR__ . '/config.php';
require __DIR__ . '/bootstrap.php';

$db = db_connect($cfg);
ensure_schema($db);
require_auth($db);

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $res = $db->query('SELECT data, version FROM app_data WHERE id = 1 LIMIT 1');
    $row = $res ? $res->fetch_assoc() : null;
    if (!$row) {
        echo json_encode(['data' => null, 'version' => 0]);
    } else {
        echo json_encode(['data' => json_decode($row['data']), 'version' => (int)$row['version']]);
    }
    exit;
}

if ($method === 'POST') {
    $raw = (string)file_get_contents('php://input');
    if (strlen($raw) > 10 * 1024 * 1024) {
        http_response_code(413);
        echo json_encode(['ok' => false, 'error' => 'trop volumineux']);
        exit;
    }
    $body = json_decode($raw, true);
    if (!is_array($body) || !array_key_exists('data', $body)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'requête invalide']);
        exit;
    }
    $clientVersion = isset($body['version']) ? (int)$body['version'] : 0;
    $dataJson = json_encode($body['data'], JSON_UNESCAPED_UNICODE);
    if ($dataJson === false) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'données invalides']);
        exit;
    }

    $db->begin_transaction();
    $res = $db->query('SELECT version, data FROM app_data WHERE id = 1 FOR UPDATE');
    $row = $res ? $res->fetch_assoc() : null;
    $curVersion = $row ? (int)$row['version'] : 0;

    if ($row && $curVersion !== $clientVersion) {
        $db->commit();
        http_response_code(409);
        echo json_encode([
            'ok' => false,
            'conflict' => true,
            'version' => $curVersion,
            'data' => json_decode($row['data']),
        ]);
        exit;
    }

    $newVersion = $curVersion + 1;
    if ($row) {
        $stmt = $db->prepare('UPDATE app_data SET data = ?, version = ?, updated_at = NOW() WHERE id = 1');
        $stmt->bind_param('si', $dataJson, $newVersion);
    } else {
        $stmt = $db->prepare('INSERT INTO app_data (id, data, version, updated_at) VALUES (1, ?, ?, NOW())');
        $stmt->bind_param('si', $dataJson, $newVersion);
    }
    $stmt->execute();
    $db->commit();

    echo json_encode(['ok' => true, 'version' => $newVersion]);
    exit;
}

http_response_code(405);
echo json_encode(['ok' => false, 'error' => 'méthode non supportée']);
