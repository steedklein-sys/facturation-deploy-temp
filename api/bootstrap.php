<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');

function db_connect(array $cfg): mysqli
{
    mysqli_report(MYSQLI_REPORT_OFF);
    $c = @new mysqli($cfg['db']['host'], $cfg['db']['user'], $cfg['db']['pass'], $cfg['db']['name'], $cfg['db']['port']);
    if ($c->connect_errno) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'base de données indisponible']);
        exit;
    }
    $c->set_charset('utf8mb4');
    return $c;
}

function ensure_schema(mysqli $db): void
{
    $db->query(
        'CREATE TABLE IF NOT EXISTS app_data (
            id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
            data LONGTEXT NOT NULL,
            version INT UNSIGNED NOT NULL DEFAULT 0,
            updated_at DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );
    $db->query(
        'CREATE TABLE IF NOT EXISTS auth_tokens (
            token_hash CHAR(64) NOT NULL PRIMARY KEY,
            created_at DATETIME NOT NULL,
            last_used_at DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );
}

function current_token(): ?string
{
    $tok = $_COOKIE['authtok'] ?? null;
    return (is_string($tok) && $tok !== '') ? $tok : null;
}

function deny(): void
{
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'non authentifié']);
    exit;
}

function require_auth(mysqli $db): void
{
    $tok = current_token();
    if (!$tok) {
        deny();
    }
    $hash = hash('sha256', $tok);
    $stmt = $db->prepare('SELECT 1 FROM auth_tokens WHERE token_hash = ? LIMIT 1');
    $stmt->bind_param('s', $hash);
    $stmt->execute();
    $res = $stmt->get_result();
    if (!$res || $res->num_rows === 0) {
        deny();
    }
    $upd = $db->prepare('UPDATE auth_tokens SET last_used_at = NOW() WHERE token_hash = ?');
    $upd->bind_param('s', $hash);
    $upd->execute();
}
