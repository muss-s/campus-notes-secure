<?php
declare(strict_types=1);

// Errors: log, never display (issue 8).
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

set_exception_handler(function (Throwable $e): void {
    error_log('Unhandled: ' . get_class($e) . ' ' . $e->getMessage());
    if (!headers_sent()) {
        http_response_code(500);
    }
    echo str_contains((string)($_SERVER['SCRIPT_NAME'] ?? ''), 'api.php')
        ? json_encode(['error' => 'Server error'])
        : 'Something went wrong. Please try again.';
    exit;
});

// Security headers (XSS defense in depth).
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');

// Session hardening (issue 6). Add 'secure' => true when served over HTTPS.
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Strict',
    'secure' => !empty($_SERVER['HTTPS']),
]);
session_start();

// DB config only from environment; no root/empty-password fallback (issue 8).
function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $user = getenv('LAB_DB_USER');
        $pass = getenv('LAB_DB_PASSWORD');
        if ($user === false || $user === '' || $pass === false) {
            throw new RuntimeException('LAB_DB_USER / LAB_DB_PASSWORD not set');
        }
        $host = getenv('LAB_DB_HOST') ?: '127.0.0.1';
        $pdo = new PDO("mysql:host=$host;dbname=notes_lab;charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
    return $pdo;
}

// Output escaping (issue 4).
function e(mixed $v): string
{
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// CSRF (issues 5, 11).
function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_valid(?string $token): bool
{
    return is_string($token) && isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

// Same-origin check: Origin (or Referer) host must match our Host.
function same_origin(): bool
{
    $src = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
    if ($src === '') {
        return false;
    }
    return parse_url($src, PHP_URL_HOST) === parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST)
        && parse_url($src, PHP_URL_PORT) === parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_PORT);
}

function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
}

function destroy_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', ['expires' => time() - 3600, 'path' => $p['path'],
            'httponly' => true, 'samesite' => 'Strict', 'secure' => $p['secure']]);
    }
    session_destroy();
}
