<?php
require __DIR__ . '/app/config/db.php';

$msg = null;
$resetLink = null;

function e(string $v): string {
  return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $email = trim($_POST['email'] ?? '');

  // Always show a generic message (do not reveal if email exists)
  $msg = "If the email exists, a reset link has been generated.";

  if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    // Find user
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    if ($user) {
      // Generate token
      $token = bin2hex(random_bytes(32)); // raw token to send to user
      $tokenHash = hash('sha256', $token); // store hash in DB
      $expiresAt = (new DateTime('+30 minutes'))->format('Y-m-d H:i:s');

      // Optional: invalidate old tokens for this user (clean)
      $pdo->prepare("DELETE FROM password_resets WHERE user_id = :uid")->execute(['uid' => $user['id']]);

      // Store new token
      $stmt = $pdo->prepare("
        INSERT INTO password_resets (user_id, token_hash, expires_at)
        VALUES (:uid, :th, :exp)
      ");
      $stmt->execute([
        'uid' => $user['id'],
        'th'  => $tokenHash,
        'exp' => $expiresAt
      ]);

      // For school: display the link (in real world you'd email it)
      $resetLink = "http://localhost/auth-system/reset_password.php?token=" . $token;
    }
  }
}
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Forgot Password</title>
</head>
<body>
  <h1>Forgot Password</h1>

  <?php if ($msg): ?>
    <p style="color: green;"><?php echo e($msg); ?></p>
  <?php endif; ?>

  <?php if ($resetLink): ?>
    <p><strong>Reset Link (demo):</strong> <a href="<?php echo e($resetLink); ?>"><?php echo e($resetLink); ?></a></p>
  <?php endif; ?>

  <form method="post" action="">
    <label>Email</label><br>
    <input type="email" name="email" required>
    <button type="submit">Generate Reset Link</button>
  </form>

  <p><a href="login.php">Back to login</a></p>
</body>
</html>
