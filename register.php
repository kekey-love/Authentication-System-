<?php
require __DIR__ . '/app/config/db.php';

$errors = [];
$success = null;

// Helper to safely display text back into HTML
function e(string $value): string {
  return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

$name  = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // 1) Collect + trim inputs
  $name = trim($_POST['name'] ?? '');
  $email = trim($_POST['email'] ?? '');
  $password = $_POST['password'] ?? '';
  $confirm  = $_POST['confirm_password'] ?? '';

  // 2) Validate
  if ($name === '' || strlen($name) < 2 || strlen($name) > 100) {
    $errors[] = "Name must be between 2 and 100 characters.";
  }

  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "Please enter a valid email address.";
  }

  if (strlen($password) < 8) {
    $errors[] = "Password must be at least 8 characters.";
  }

  if ($password !== $confirm) {
    $errors[] = "Passwords do not match.";
  }

  // 3) If valid so far, check if email already exists
  if (!$errors) {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $stmt->execute(['email' => $email]);
    $existing = $stmt->fetch();

    if ($existing) {
      $errors[] = "An account with that email already exists.";
    }
  }

  // 4) If still no errors, hash password + insert user
  if (!$errors) {
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $pdo->prepare("
      INSERT INTO users (name, email, password_hash)
      VALUES (:name, :email, :password_hash)
    ");

    $stmt->execute([
      'name' => $name,
      'email' => $email,
      'password_hash' => $passwordHash
    ]);

    $success = "Account created successfully. You can now log in.";

    // Clear form values after success
    $name = '';
    $email = '';
  }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Register</title>
</head>
<body>
  <h1>Create Account</h1>

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
      <label>Name</label><br>
      <input type="text" name="name" value="<?php echo e($name); ?>" required>
    </div>

    <div>
      <label>Email</label><br>
      <input type="email" name="email" value="<?php echo e($email); ?>" required>
    </div>

    <div>
      <label>Password</label><br>
      <input type="password" name="password" required>
    </div>

    <div>
      <label>Confirm Password</label><br>
      <input type="password" name="confirm_password" required>
    </div>

    <button type="submit">Register</button>
  </form>

  <p>Already have an account? <a href="login.php">Login</a></p>
</body>
</html>
