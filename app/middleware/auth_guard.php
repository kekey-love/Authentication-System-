<?php
// app/middleware/auth_guard.php
session_start();

if (!isset($_SESSION['user_id'])) {
  header("Location: /auth-system/login.php");
  exit;
}
