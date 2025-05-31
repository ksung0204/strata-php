<?php
require_once __DIR__ . '/includes/session.php';

// Logout the user
logout();

// Redirect to login page
header('Location: /api/pages/login.php');
exit();
?> 