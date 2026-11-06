<?php
declare(strict_types=1);

// All note queries are parameterized and scoped to the owner (issues 1, 3, 7, 9).

function notes_for_user(int $uid): array
{
    $s = db()->prepare('SELECT id, user_id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC');
    $s->execute([$uid]);
    return $s->fetchAll();
}

function note_for_user(int $id, int $uid): array|false
{
    $s = db()->prepare('SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?');
    $s->execute([$id, $uid]);
    return $s->fetch();
}

function create_note(int $uid, string $title, string $body): void
{
    db()->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)')->execute([$uid, $title, $body]);
}

function update_note(int $id, int $uid, string $title, string $body): int
{
    $s = db()->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
    $s->execute([$title, $body, $id, $uid]);
    return $s->rowCount();
}

function delete_note(int $id, int $uid): int
{
    $s = db()->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
    $s->execute([$id, $uid]);
    return $s->rowCount();
}

// Returns an error string or null. Matches schema limits (title 120).
function validate_note(mixed $title, mixed $body): ?string
{
    if (!is_string($title) || !is_string($body)) {
        return 'Title and body must be text.';
    }
    $title = trim($title);
    if ($title === '' || mb_strlen($title) > 120) {
        return 'Title is required (max 120 characters).';
    }
    if (trim($body) === '' || mb_strlen($body) > 10000) {
        return 'Body is required (max 10000 characters).';
    }
    return null;
}
