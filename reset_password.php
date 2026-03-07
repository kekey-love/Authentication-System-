<?php
require __DIR__ . '/app/config/db.php';

function e(string $v): string {
  return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

$errors = [];
$success = null;

$token = $_GET['token'] ?? '';
$token = trim($token);

if ($token === '' || !ctype_xdigit($token) || strlen($token) < 20) {
  $errors[] = "Invalid or missing reset token.";
}

// If token looks okay, find matching reset record
$resetRow = null;

if (!$errors) {
  $tokenHash = hash('sha256', $token);

  $stmt = $pdo->prepare("
    SELECT pr.id, pr.user_id, pr.expires_at, pr.used_at
    FROM password_resets pr
    WHERE pr.token_hash = :th
    LIMIT 1
  ");
  $stmt->execute(['th' => $tokenHash]);
  $resetRow = $stmt->fetch();

  if (!$resetRow) {
    $errors[] = "Reset link is invalid or has expired.";
  } else {
    // Check expiry + used
    $now = new DateTime();
    $expires = new DateTime($resetRow['expires_at']);

    if ($resetRow['used_at'] !== null) {
      $errors[] = "This reset link has already been used.";
    } elseif ($expires < $now) {
      $errors[] = "Reset link has expired.";
    }
  }
}

// Handle password update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$errors && $resetRow) {
  $password = $_POST['password'] ?? '';
  $confirm  = $_POST['confirm_password'] ?? '';

  if (strlen($password) < 8) {
    $errors[] = "Password must be at least 8 characters.";
  }
  if ($password !== $confirm) {
    $errors[] = "Passwords do not match.";
  }

  if (!$errors) {
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    // Update user password
    $stmt = $pdo->prepare("UPDATE users SET password_hash = :ph WHERE id = :uid");
    $stmt->execute([
      'ph'  => $passwordHash,
      'uid' => $resetRow['user_id']
    ]);

    // Mark token as used
    $stmt = $pdo->prepare("UPDATE password_resets SET used_at = NOW() WHERE id = :id");
    $stmt->execute(['id' => $resetRow['id']]);

    $success = "Password updated successfully. You can now log in.";
  }
}
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Reset Password</title>
</head>
<body>
  <h1>Reset Password</h1>

  <?php if ($success): ?>
    <p style="color: green;"><?php echo e($success); ?></p>
    <p><a href="login.php">Go to login</a></p>
  <?php else: ?>

    <?php if ($errors): ?>
      <ul style="color: red;">
        <?php foreach ($errors as $err): ?>
          <li><?php echo e($err); ?></li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>

    <?php if (!$errors): ?>
      <form method="post" action="">
        <div>
          <label>New Password</label><br>
          <input type="password" name="password" required>
        </div>

        <div>
          <label>Confirm New Password</label><br>
          <input type="password" name="confirm_password" required>
        </div>

        <button type="submit">Reset Password</button>
      </form>
    <?php endif; ?>

  <?php endif; ?>
</body>
</html>
