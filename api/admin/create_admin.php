<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

$error = '';
$success = '';

// Check if user is admin or if this is the initial setup (no admin exists)
$stmt = $pdo->query('SELECT COUNT(*) as admin_count FROM users WHERE role = \'admin\'');
$adminCount = $stmt->fetchColumn();

$isInitialSetup = $adminCount == 0;
$canCreateAdmin = $isInitialSetup || hasRole('admin');

if (!$canCreateAdmin) {
    http_response_code(403);
    echo '<h1>403 Forbidden</h1><p>Only administrators can create admin accounts.</p>';
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection (only if not initial setup)
    if (!$isInitialSetup) {
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!validateCSRFToken($csrfToken)) {
            $error = 'Invalid request. Please try again.';
        }
    }
    
    if (empty($error)) {
        $username = sanitizeInput($_POST['username'] ?? '');
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        // Validation
        if (empty($username) || empty($email) || empty($password) || empty($confirmPassword)) {
            $error = 'Please fill in all fields.';
        } elseif (!validateEmail($email)) {
            $error = 'Invalid email address.';
        } elseif (!validatePassword($password)) {
            $error = 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.';
        } elseif ($password !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } elseif (strlen($username) < 3) {
            $error = 'Username must be at least 3 characters long.';
        } else {
            try {
                // Check if email already exists
                $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    $error = 'Email is already registered.';
                } else {
                    // Check if username already exists
                    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ?');
                    $stmt->execute([$username]);
                    if ($stmt->fetch()) {
                        $error = 'Username is already taken.';
                    } else {
                        // Hash the password with strong settings
                        $hashed_password = password_hash($password, PASSWORD_ARGON2ID, [
                            'memory_cost' => 65536,
                            'time_cost' => 4,
                            'threads' => 3
                        ]);
                        
                        // Insert admin user
                        $stmt = $pdo->prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)');
                        if ($stmt->execute([$username, $email, $hashed_password, 'admin'])) {
                            $success = 'Admin account created successfully!';
                            
                            // If this was initial setup, redirect to login
                            if ($isInitialSetup) {
                                $success .= ' You can now <a href="/api/pages/login.php">login</a>.';
                            }
                        } else {
                            $error = 'Failed to create admin account. Please try again.';
                        }
                    }
                }
            } catch (PDOException $e) {
                error_log('Admin creation error: ' . $e->getMessage());
                $error = 'Failed to create admin account. Please try again.';
            }
        }
    }
}

if (!$isInitialSetup) {
    $csrfToken = generateCSRFToken();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $isInitialSetup ? 'Initial Setup' : 'Create Admin Account'; ?> - Strata Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h3 class="text-center mb-0">
                            <?php echo $isInitialSetup ? '🔐 Initial Admin Setup' : '👑 Create Admin Account'; ?>
                        </h3>
                    </div>
                    <div class="card-body">
                        <?php if ($isInitialSetup): ?>
                            <div class="alert alert-warning">
                                <strong>Initial Setup:</strong> No admin accounts exist. Creating the first admin account.
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                        <?php elseif ($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>
                        
                        <?php if (!$success): ?>
                        <form method="POST" action="/api/admin/create_admin.php">
                            <?php if (!$isInitialSetup): ?>
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                            <?php endif; ?>
                            
                            <div class="mb-3">
                                <label for="username" class="form-label">Admin Username</label>
                                <input type="text" class="form-control" id="username" name="username" 
                                       value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" 
                                       minlength="3" maxlength="50" required>
                                <div class="form-text">Username must be at least 3 characters long.</div>
                            </div>
                            <div class="mb-3">
                                <label for="email" class="form-label">Admin Email</label>
                                <input type="email" class="form-control" id="email" name="email" 
                                       value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" 
                                       minlength="8" required>
                                <div class="form-text">Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.</div>
                            </div>
                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" 
                                       minlength="8" required>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-danger">Create Admin Account</button>
                            </div>
                        </form>
                        <?php endif; ?>
                        
                        <?php if (!$isInitialSetup): ?>
                        <div class="mt-3 text-center">
                            <a href="/api/index.php" class="btn btn-secondary">Back to Dashboard</a>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Client-side password validation
        document.getElementById('confirm_password').addEventListener('input', function() {
            const password = document.getElementById('password').value;
            const confirmPassword = this.value;
            
            if (password !== confirmPassword) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
        
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            const hasMinLength = password.length >= 8;
            
            if (!hasMinLength || !hasUpper || !hasLower || !hasNumber) {
                this.setCustomValidity('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.');
            } else {
                this.setCustomValidity('');
            }
        });
    </script>
</body>
</html> 