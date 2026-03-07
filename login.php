<?php
require __DIR__ . '/app/config/db.php';
session_start();

$errors = [];

function e(string $value): string {
  return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $email = trim($_POST['email'] ?? '');
  $password = $_POST['password'] ?? '';

  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "Enter a valid email.";
  }

  if ($password === '') {
    $errors[] = "Password is required.";
  }

  if (!$errors) {
    $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE email = :email LIMIT 1");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    // Always use a generic error for security
    if (!$user || !password_verify($password, $user['password_hash'])) {
      $errors[] = "Invalid login details.";
    } else {
      session_regenerate_id(true);
      $_SESSION['user_id'] = $user['id'];
      header("Location: dashboard.php");
      exit;
    }
  }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>
</head>
<body>
  <h1>Login</h1>

  <?php if ($errors): ?>
    <ul style="color: red;">
      <?php foreach ($errors as $err): ?>
        <li><?php echo e($err); ?></li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>

  <form method="post" action="">
    <div>
      <label>Email</label><br>
      <input type="email" name="email" value="<?php echo e($email); ?>" required>
    </div>

    <div>
      <label>Password</label><br>
      <input type="password" name="password" required>
    </div>

    <button type="submit">Login</button>
  </form>

  <p><a href="forgot_password.php">Forgot password?</a></p>
  <p>Don’t have an account? <a href="register.php">Register</a></p>
</body>
</html>
