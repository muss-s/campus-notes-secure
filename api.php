<?php
declare(strict_types=1);
require __DIR__ . '/src/bootstrap.php';
require __DIR__ . '/src/notes.php';

// No CORS headers: the API is same-origin only (issue 11). The old code reflected any
// Origin with credentials allowed, which let any site read/modify notes via the cookie.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function out(int $code, array $data): never
{
    http_response_code($code);
    echo json_encode($data);
    exit;
}

$uid = current_user_id();
if ($uid === null) {
    out(401, ['error' => 'Authentication required']); // issue 9
}

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // Owner comes from the session. A user_id param for someone else is refused (issue 9).
    if (isset($_GET['user_id']) && (string)$_GET['user_id'] !== (string)$uid) {
        out(403, ['error' => 'Forbidden']);
    }
    header('X-CSRF-Token: ' . csrf_token()); // for same-origin scripts to use on POST
    out(200, notes_for_user($uid));
}

if ($method === 'POST') {
    if (!same_origin() || !csrf_valid($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
        out(403, ['error' => 'Forbidden']); // issue 11
    }
    // JSON only: a plain HTML form cannot send this content type cross-site.
    $ct = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    if ($ct !== 'application/json') {
        out(415, ['error' => 'Content-Type must be application/json']);
    }
    $raw = file_get_contents('php://input', false, null, 0, 65537);
    if ($raw === false || strlen($raw) > 65536) {
        out(413, ['error' => 'Body too large']);
    }
    try {
        $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR); // issue 10
    } catch (JsonException) {
        out(400, ['error' => 'Invalid JSON']);
    }
    if (!is_array($data) || !isset($data['id']) || (!is_int($data['id']) && !(is_string($data['id']) && ctype_digit($data['id'])))) {
        out(422, ['error' => 'id is required']);
    }
    $err = validate_note($data['title'] ?? null, $data['body'] ?? null);
    if ($err !== null) {
        out(422, ['error' => $err]);
    }
    $n = update_note((int)$data['id'], $uid, trim($data['title']), $data['body']);
    // Same response whether the note is missing or belongs to someone else.
    out($n > 0 ? 200 : 404, $n > 0 ? ['updated' => 1] : ['error' => 'Not found']);
}

header('Allow: GET, POST');
out(405, ['error' => 'Method not supported']);
