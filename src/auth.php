<?php
declare(strict_types=1);

// Passwords: password_hash/password_verify (issue 2). Role is never client-supplied (issue 7).

function register_user(string $email, string $password): ?string
{
    $email = trim($email);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
        return 'Enter a valid email.';
    }
    if (strlen($password) < 10 || strlen($password) > 200) {
        return 'Password must be 10-200 characters.';
    }
    try {
        db()->prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, \'student\')')
            ->execute([$email, password_hash($password, PASSWORD_DEFAULT)]);
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') { // duplicate email: do not reveal
            return null;
        }
        throw $e;
    }
    return null;
}

function login_user(string $email, string $password): bool
{
    $s = db()->prepare('SELECT id, password_hash, role FROM users WHERE email = ?');
    $s->execute([trim($email)]);
    $u = $s->fetch();
    // Constant-ish work even for unknown users.
    $hash = $u['password_hash'] ?? '$2y$10$usesomesillystringforsaltuQ5Zk3f3b8W1m0v2o9x4y6z8a1b3c5d7e9g';
    if (!password_verify($password, $hash) || !$u) {
        return false;
    }
    session_regenerate_id(true); // prevent fixation (issue 6)
    $_SESSION['user_id'] = (int)$u['id'];
    $_SESSION['role'] = $u['role'];
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    if (password_needs_rehash($u['password_hash'], PASSWORD_DEFAULT)) {
        db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
            ->execute([password_hash($password, PASSWORD_DEFAULT), $u['id']]);
    }
    return true;
}
