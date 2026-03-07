<?php
require __DIR__ . '/app/middleware/auth_guard.php';
require __DIR__ . '/app/config/db.php';

$errors = [];
$success = null;

function e(string $v): string {
  return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $current = $_POST['current_password'] ?? '';
  $newPass = $_POST['new_password'] ?? '';
  $confirm = $_POST['confirm_password'] ?? '';

  if ($current === '') $errors[] = "Current password is required.";
  if (strlen($newPass) < 8) $errors[] = "New password must be at least 8 characters.";
  if ($newPass !== $confirm) $errors[] = "New passwords do not match.";

  if (!$errors) {
    $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = :id LIMIT 1");
    $stmt->execute(['id' => $_SESSION['user_id']]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($current, $user['password_hash'])) {
      $errors[] = "Current password is incorrect.";
    } else {
      $newHash = password_hash($newPass, PASSWORD_DEFAULT);

      $stmt = $pdo->prepare("UPDATE users SET password_hash = :ph WHERE id = :id");
      $stmt->execute(['ph' => $newHash, 'id' => $_SESSION['user_id']]);

      $success = "Password changed successfully.";
    }
  }
}
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Change Password</title>
</head>
<body>
  <h1>Change Password</h1>

  <?php if ($success): ?>
    <p style="color: green;"><?php echo e($success); ?></p>
  <?php endif; ?>

  <?php if ($errors): ?>
    <ul style="color: red;">
      <?php foreach ($errors as $err): ?>
        <li><?php echo e($err); ?></li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>

  <form method="post" action="">
    <div>
      <label>Current Password</label><br>
      <input type="password" name="current_password" required>
    </div>

    <div>
      <label>New Password</label><br>
      <input type="password" name="new_password" required>
    </div>

    <div>
      <label>Confirm New Password</label><br>
      <input type="password" name="confirm_password" required>
    </div>

    <button type="submit">Change Password</button>
  </form>

  <p><a href="dashboard.php">Back to dashboard</a></p>
</html>
