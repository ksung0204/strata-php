<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

$error = '';
$success = '';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: /api/index.php');
    exit();
}

// Define allowed roles for registration (admin role should be restricted)
$allowedRoles = ['owner', 'committee'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $username = sanitizeInput($_POST['username'] ?? '');
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        $role = $_POST['role'] ?? 'owner';

        // Validation
        if (empty($username) || empty($email) || empty($password) || empty($confirmPassword) || empty($role)) {
            $error = 'Please fill in all fields.';
        } elseif (!validateEmail($email)) {
            $error = 'Invalid email address.';
        } elseif (!validatePassword($password)) {
            $error = 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.';
        } elseif ($password !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } elseif (!in_array($role, $allowedRoles)) {
            $error = 'Invalid role selected.';
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
                        
                        // Insert user
                        $stmt = $pdo->prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)');
                        if ($stmt->execute([$username, $email, $hashed_password, $role])) {
                            $success = 'Registration successful! You can now <a href="/api/pages/login.php">login</a>.';
                        } else {
                            $error = 'Registration failed. Please try again.';
                        }
                    }
                }
            } catch (PDOException $e) {
                error_log('Registration error: ' . $e->getMessage());
                $error = 'Registration failed. Please try again.';
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
    <title>Register - Strata Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">Register</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                        <?php elseif ($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>
                        
                        <?php if (!$success): ?>
                        <form method="POST" action="/api/pages/register.php">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                            
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" 
                                       value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" 
                                       minlength="3" maxlength="50" required>
                                <div class="form-text">Username must be at least 3 characters long.</div>
                            </div>
                            <div class="mb-3">
                                <label for="email" class="form-label">Email address</label>
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
                            <div class="mb-3">
                                <label for="role" class="form-label">Role</label>
                                <select class="form-select" id="role" name="role" required>
                                    <option value="">Select a role</option>
                                    <?php foreach ($allowedRoles as $allowedRole): ?>
                                        <option value="<?php echo htmlspecialchars($allowedRole); ?>"
                                                <?php echo (($_POST['role'] ?? '') === $allowedRole) ? 'selected' : ''; ?>>
                                            <?php echo ucfirst(htmlspecialchars($allowedRole)); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <div class="form-text">Select your role in the strata community.</div>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">Register</button>
                            </div>
                        </form>
                        <?php endif; ?>
                        
                        <div class="mt-3 text-center">
                            Already have an account? <a href="/api/pages/login.php">Login here</a>.
                        </div>
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