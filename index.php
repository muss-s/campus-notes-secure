<?php
declare(strict_types=1);
require __DIR__ . '/src/bootstrap.php';
require __DIR__ . '/src/auth.php';
require __DIR__ . '/src/notes.php';

$message = '';
$uid = current_user_id();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Every state change is POST + CSRF token + same-origin (issue 5).
    // Login/register have no session yet, so they get a token from the pre-login session too.
    if (!csrf_valid($_POST['csrf'] ?? null) || !same_origin()) {
        http_response_code(403);
        exit('Invalid request.');
    }
    $action = $_POST['action'] ?? '';
    $str = fn(string $k): string => is_string($_POST[$k] ?? null) ? $_POST[$k] : '';

    if ($action === 'register' && $uid === null) {
        $err = register_user($str('email'), $str('password'));
        $message = $err ?? 'If that email is free, the account was created. Please sign in.';
    } elseif ($action === 'login' && $uid === null) {
        if (login_user($str('email'), $str('password'))) {
            header('Location: /');
            exit;
        }
        $message = 'Login failed.'; // generic, no echo of input
    } elseif ($uid !== null) {
        if ($action === 'logout') {
            destroy_session();
            header('Location: /');
            exit;
        }
        if ($action === 'save' || $action === 'update') {
            $err = validate_note($_POST['title'] ?? null, $_POST['body'] ?? null);
            if ($err === null) {
                // Owner always comes from the session, never from the form (issue 7).
                if ($action === 'save') {
                    create_note($uid, trim($str('title')), $str('body'));
                } else {
                    update_note((int)$str('id'), $uid, trim($str('title')), $str('body'));
                }
                header('Location: /');
                exit;
            }
            $message = $err;
        } elseif ($action === 'delete') {
            delete_note((int)$str('id'), $uid);
            header('Location: /');
            exit;
        }
    }
}

$notes = [];
$editing = false;
if ($uid !== null) {
    $notes = notes_for_user($uid);
    if (isset($_GET['edit']) && is_string($_GET['edit']) && ctype_digit($_GET['edit'])) {
        $editing = note_for_user((int)$_GET['edit'], $uid); // owner-scoped
    }
}
$csrf = csrf_token();
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Campus Notes</title>
<style>body{font:16px sans-serif;max-width:750px;margin:2rem auto}label{display:block;margin:.5rem 0}article{border:1px solid #aaa;padding:1rem;margin:1rem 0}.inline{display:inline}</style>
</head>
<body>
<h1>Campus Notes</h1>
<p><?= e($message) ?></p>
<?php if ($uid === null): ?>
<h2>Register or sign in</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <label>Email <input name="email" type="email" required maxlength="254"></label>
  <label>Password <input name="password" type="password" required minlength="10"></label>
  <button name="action" value="register">Register</button>
  <button name="action" value="login">Sign in</button>
</form>
<?php else: ?>
<form method="post" class="inline">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  User ID: <?= e($uid) ?> | Role: <?= e($_SESSION['role'] ?? '') ?> |
  <button name="action" value="logout">Log out</button>
</form>
<?php if ($editing): ?>
<h2>Edit note</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <input type="hidden" name="id" value="<?= e($editing['id']) ?>">
  <label>Title <input name="title" value="<?= e($editing['title']) ?>" required maxlength="120"></label>
  <label>Body <textarea name="body" required><?= e($editing['body']) ?></textarea></label>
  <button name="action" value="update">Update</button>
  <a href="/">Cancel</a>
</form>
<?php endif; ?>
<h2>Create a note</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <label>Title <input name="title" required maxlength="120"></label>
  <label>Body <textarea name="body" required></textarea></label>
  <button name="action" value="save">Save</button>
</form>
<h2>Notes</h2>
<?php foreach ($notes as $note): ?>
<article><h3><?= e($note['title']) ?></h3><p><?= e($note['body']) ?></p>
<a href="?edit=<?= e($note['id']) ?>">Edit</a>
<form method="post" class="inline">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <input type="hidden" name="id" value="<?= e($note['id']) ?>">
  <button name="action" value="delete">Delete</button>
</form></article>
<?php endforeach; ?>
<?php endif; ?>
</body></html>
