<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

$error = '';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: /api/index.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($email) || empty($password)) {
            $error = 'Please fill in all fields';
        } elseif (!validateEmail($email)) {
            $error = 'Invalid email format';
        } else {
            // Rate limiting based on IP address
            $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            if (!checkRateLimit($clientIP)) {
                $error = 'Too many login attempts. Please try again later.';
            } else {
                try {
                    $stmt = $pdo->prepare('SELECT id, username, password, role FROM users WHERE email = ?');
                    $stmt->execute([$email]);
                    $user = $stmt->fetch();

                    if ($user && password_verify($password, $user['password'])) {
                        // Successful login
                        loginUser($user['id'], $user['username'], $user['role']);
                        resetLoginAttempts($clientIP);
                        header('Location: /api/index.php');
                        exit();
                    } else {
                        // Failed login
                        recordFailedLogin($clientIP);
                        $error = 'Invalid email or password';
                    }
                } catch (PDOException $e) {
                    error_log('Login error: ' . $e->getMessage());
                    $error = 'Login failed. Please try again.';
                }
            }
        }
    }
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Strata Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">Login</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                        <?php endif; ?>
                        
                        <form method="POST" action="/api/pages/login.php">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                            
                            <div class="mb-3">
                                <label for="email" class="form-label">Email address</label>
                                <input type="email" class="form-control" id="email" name="email" 
                                       value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">Login</button>
                            </div>
                        </form>
                        <div class="mt-3 text-center">
                            Don't have an account? <a href="/api/pages/register.php">Register here</a>.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 