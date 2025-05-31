<?php
// api/index.php
require_once __DIR__ . '/includes/session.php';

$currentUser = getCurrentUser();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Strata Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/api/index.php">Strata Management</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/api/index.php">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/public_info.php">Building Info</a>
                    </li>
                    <?php if (isLoggedIn()): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/api/pages/documents.php">Documents</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/api/pages/maintenance.php">Maintenance</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/api/pages/levies.php">Levies</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/api/pages/owners.php">Owners Directory</a>
                        </li>
                        <?php if (hasAnyRole(['committee', 'admin'])): ?>
                            <li class="nav-item dropdown">
                                <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                                    Management
                                </a>
                                <ul class="dropdown-menu">
                                    <li><a class="dropdown-item" href="/api/pages/budget.php">Budget Management</a></li>
                                    <li><a class="dropdown-item" href="/api/pages/generate_levies.php">Generate Levy Notices</a></li>
                                    <?php if (hasRole('admin')): ?>
                                        <li><hr class="dropdown-divider"></li>
                                        <li><a class="dropdown-item" href="/api/admin/create_admin.php">Create Admin</a></li>
                                    <?php endif; ?>
                                </ul>
                            </li>
                        <?php endif; ?>
                    <?php endif; ?>
                </ul>
                
                <ul class="navbar-nav ms-auto">
                    <?php if (isLoggedIn()): ?>
                        <li class="nav-item">
                            <span class="navbar-text me-3">
                                Welcome, <?php echo htmlspecialchars($currentUser['username']); ?>
                                <span class="badge bg-<?php 
                                    echo $currentUser['role'] === 'admin' ? 'danger' : 
                                        ($currentUser['role'] === 'committee' ? 'warning' : 'primary'); 
                                ?>"><?php echo htmlspecialchars(ucfirst($currentUser['role'])); ?></span>
                            </span>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/api/logout.php">Logout</a>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/api/pages/login.php">Login</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/api/pages/register.php">Register</a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <?php if (!isLoggedIn()): ?>
            <div class="alert alert-info">
                <h5>Welcome to Strata Management System</h5>
                <p>Please <a href="/api/pages/login.php" class="alert-link">login</a> or <a href="/api/pages/register.php" class="alert-link">register</a> to access the system.</p>
                <p>View general <a href="/public_info.php" class="alert-link">building information</a> available to the public.</p>
            </div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-8">
                <h1>Welcome to Strata Management System</h1>
                <p class="lead">Efficiently manage your strata property with our comprehensive management system compliant with NSW Strata Schemes Management Act 2015.</p>
                
                <?php if (isLoggedIn()): ?>
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title">Quick Links</h5>
                                <ul class="list-unstyled">
                                    <li><a href="/api/pages/documents.php" class="text-decoration-none">📄 View Documents</a></li>
                                    <li><a href="/api/pages/maintenance.php" class="text-decoration-none">🔧 Submit Maintenance Request</a></li>
                                    <li><a href="/api/pages/levies.php" class="text-decoration-none">💰 Pay Levies</a></li>
                                    <li><a href="/api/pages/owners.php" class="text-decoration-none">👥 Owners Directory</a></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    
                    <?php if (hasAnyRole(['committee', 'admin'])): ?>
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title">Management Tools</h5>
                                <ul class="list-unstyled">
                                    <li><a href="/api/pages/budget.php" class="text-decoration-none">📊 Budget Management</a></li>
                                    <li><a href="/api/pages/generate_levies.php" class="text-decoration-none">📋 Generate Levy Notices</a></li>
                                    <?php if (hasRole('admin')): ?>
                                        <li><a href="/api/admin/create_admin.php" class="text-decoration-none">👑 Create Admin Account</a></li>
                                    <?php endif; ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Building Information</h5>
                        <p class="card-text">Skyline Apartments - Modern strata-titled complex with 120 units across 15 floors.</p>
                        <a href="/public_info.php" class="btn btn-primary">View Details</a>
                    </div>
                </div>
                
                <?php if (isLoggedIn()): ?>
                <div class="card mt-3">
                    <div class="card-body">
                        <h6 class="card-title">Your Account</h6>
                        <p class="card-text">
                            <strong>Role:</strong> <?php echo htmlspecialchars(ucfirst($currentUser['role'])); ?><br>
                            <strong>Username:</strong> <?php echo htmlspecialchars($currentUser['username']); ?><br>
                            <strong>Email:</strong> <?php echo htmlspecialchars($currentUser['email'] ?? 'Not available'); ?>
                        </p>
                    </div>
                </div>
                
                <div class="card mt-3">
                    <div class="card-body">
                        <h6 class="card-title">System Features</h6>
                        <ul class="list-unstyled small">
                            <li>✅ Document storage and access</li>
                            <li>✅ Maintenance request tracking</li>
                            <li>✅ Levy management and payment</li>
                            <li>✅ Owners directory and contact details</li>
                            <li>✅ Budget planning and tracking</li>
                            <li>✅ Automated levy generation</li>
                            <li>✅ Role-based access control</li>
                            <li>✅ NSW Strata Act compliance</li>
                        </ul>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <?php if (!isLoggedIn()): ?>
        <!-- Public Features Section -->
        <div class="row mt-5">
            <div class="col-12">
                <h2>System Features</h2>
                <p class="text-muted">Comprehensive strata management solution for NSW apartment buildings</p>
            </div>
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">📄 Document Management</h5>
                        <p class="card-text">Secure storage and access to important documents including insurance certificates, financial reports, and meeting minutes.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">💰 Financial Management</h5>
                        <p class="card-text">Complete budget management, levy generation, and payment tracking for both administration and capital works funds.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">🔧 Maintenance Tracking</h5>
                        <p class="card-text">Submit and track maintenance requests with status updates and work order management.</p>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>