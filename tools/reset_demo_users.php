<?php
// CLI only. Resets the two public synthetic lab accounts with password_hash().
// Usage: LAB_DB_USER=... LAB_DB_PASSWORD=... php tools/reset_demo_users.php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require __DIR__ . '/../src/bootstrap.php';

$demo = [
    [1, 'alex@example.test', 'LabOnly-Alex-123'],
    [2, 'sam@example.test', 'LabOnly-Sam-456'],
];
$st = db()->prepare('UPDATE users SET password_hash = ? WHERE id = ? AND email = ?');
foreach ($demo as [$id, $email, $pw]) {
    $st->execute([password_hash($pw, PASSWORD_DEFAULT), $id, $email]);
}
echo "Demo passwords re-hashed.\n";
