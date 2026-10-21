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
    $db->query(
        "CREATE TABLE IF NOT EXISTS webauthn_credentials (
            credential_id VARBINARY(255) NOT NULL PRIMARY KEY,
            public_key_pem TEXT NOT NULL,
            sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
            label VARCHAR(100) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );
}

// Crée une session (jeton + cookie 'authtok') — utilisé après une connexion
// réussie, que ce soit par mot de passe ou par empreinte digitale (WebAuthn).
function create_session(mysqli $db): void
{
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
}

// Démarre une session PHP (utilisée brièvement pour mémoriser le "challenge"
// WebAuthn entre les deux requêtes d'une même opération) avec des réglages
// de cookie cohérents avec le reste de l'application.
function wa_session_start(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }
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
