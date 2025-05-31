<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

// Require committee or admin access
requireRole(['committee', 'admin']);

$currentUser = getCurrentUser();
$error = '';
$success = '';

// Handle form submissions for budget entries
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        if ($action === 'add_budget_item') {
            $category = sanitizeInput($_POST['category'] ?? '');
            $description = sanitizeInput($_POST['description'] ?? '');
            $budgeted_amount = floatval($_POST['budgeted_amount'] ?? 0);
            $actual_amount = floatval($_POST['actual_amount'] ?? 0);
            $fund_type = sanitizeInput($_POST['fund_type'] ?? '');
            $financial_year = sanitizeInput($_POST['financial_year'] ?? '');

            if (empty($category) || empty($description) || $budgeted_amount <= 0 || empty($fund_type)) {
                $error = 'Please fill in all required fields with valid amounts.';
            } else {
                try {
                    // Create budget_items table if it doesn't exist
                    $pdo->exec("
                        CREATE TABLE IF NOT EXISTS budget_items (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            category VARCHAR(100) NOT NULL,
                            description TEXT NOT NULL,
                            budgeted_amount DECIMAL(10,2) NOT NULL,
                            actual_amount DECIMAL(10,2) DEFAULT 0,
                            fund_type ENUM('administration', 'capital_works') NOT NULL,
                            financial_year VARCHAR(9) NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            created_by INT,
                            FOREIGN KEY (created_by) REFERENCES users(id)
                        )
                    ");

                    $stmt = $pdo->prepare('INSERT INTO budget_items (category, description, budgeted_amount, actual_amount, fund_type, financial_year, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)');
                    if ($stmt->execute([$category, $description, $budgeted_amount, $actual_amount, $fund_type, $financial_year, $currentUser['id']])) {
                        $success = 'Budget item added successfully!';
                    } else {
                        $error = 'Failed to add budget item.';
                    }
                } catch (PDOException $e) {
                    error_log('Budget item creation error: ' . $e->getMessage());
                    $error = 'Database error. Please try again.';
                }
            }
        }
    }
}

// Get current financial year
$currentFinancialYear = (date('m') >= 7) ? date('Y') . '-' . (date('Y') + 1) : (date('Y') - 1) . '-' . date('Y');

// Get budget data (HTTP GET)
try {
    // Get budget items
    $stmt = $pdo->prepare('
        SELECT bi.*, u.username as created_by_name 
        FROM budget_items bi 
        LEFT JOIN users u ON bi.created_by = u.id 
        WHERE bi.financial_year = ? 
        ORDER BY bi.fund_type, bi.category
    ');
    $stmt->execute([$currentFinancialYear]);
    $budgetItems = $stmt->fetchAll();

    // Calculate totals
    $adminBudgeted = 0;
    $adminActual = 0;
    $capitalBudgeted = 0;
    $capitalActual = 0;

    foreach ($budgetItems as $item) {
        if ($item['fund_type'] === 'administration') {
            $adminBudgeted += $item['budgeted_amount'];
            $adminActual += $item['actual_amount'];
        } else {
            $capitalBudgeted += $item['budgeted_amount'];
            $capitalActual += $item['actual_amount'];
        }
    }

} catch (PDOException $e) {
    error_log('Budget retrieval error: ' . $e->getMessage());
    $budgetItems = [];
    $adminBudgeted = $adminActual = $capitalBudgeted = $capitalActual = 0;
}

// Generate sample data if no budget items exist
if (empty($budgetItems)) {
    $budgetItems = [
        [
            'id' => 1,
            'category' => 'Insurance',
            'description' => 'Building insurance premium',
            'budgeted_amount' => 45000.00,
            'actual_amount' => 44500.00,
            'fund_type' => 'administration',
            'financial_year' => $currentFinancialYear,
            'created_by_name' => 'Admin'
        ],
        [
            'id' => 2,
            'category' => 'Maintenance',
            'description' => 'General building maintenance',
            'budgeted_amount' => 25000.00,
            'actual_amount' => 18750.00,
            'fund_type' => 'administration',
            'financial_year' => $currentFinancialYear,
            'created_by_name' => 'Admin'
        ],
        [
            'id' => 3,
            'category' => 'Utilities',
            'description' => 'Electricity and water for common areas',
            'budgeted_amount' => 15000.00,
            'actual_amount' => 12500.00,
            'fund_type' => 'administration',
            'financial_year' => $currentFinancialYear,
            'created_by_name' => 'Admin'
        ],
        [
            'id' => 4,
            'category' => 'Lift Upgrade',
            'description' => 'Replacement of lift systems',
            'budgeted_amount' => 150000.00,
            'actual_amount' => 75000.00,
            'fund_type' => 'capital_works',
            'financial_year' => $currentFinancialYear,
            'created_by_name' => 'Admin'
        ],
        [
            'id' => 5,
            'category' => 'Roof Repairs',
            'description' => 'Major roof waterproofing',
            'budgeted_amount' => 80000.00,
            'actual_amount' => 0.00,
            'fund_type' => 'capital_works',
            'financial_year' => $currentFinancialYear,
            'created_by_name' => 'Admin'
        ]
    ];

    // Recalculate totals for sample data
    foreach ($budgetItems as $item) {
        if ($item['fund_type'] === 'administration') {
            $adminBudgeted += $item['budgeted_amount'];
            $adminActual += $item['actual_amount'];
        } else {
            $capitalBudgeted += $item['budgeted_amount'];
            $capitalActual += $item['actual_amount'];
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
    <title>Budget Management - Strata Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/api/index.php">Strata Management</a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    Welcome, <?php echo htmlspecialchars($currentUser['username']); ?>
                    <span class="badge bg-<?php 
                        echo $currentUser['role'] === 'admin' ? 'danger' : 
                            ($currentUser['role'] === 'committee' ? 'warning' : 'primary'); 
                    ?>"><?php echo htmlspecialchars(ucfirst($currentUser['role'])); ?></span>
                </span>
                <a class="nav-link" href="/api/logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>📊 Budget Management</h1>
        <p class="text-muted mb-4">Manage the administration fund and capital works fund budgets for financial year <?php echo htmlspecialchars($currentFinancialYear); ?>.</p>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <!-- Budget Summary -->
        <div class="row mb-4">
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">💼 Administration Fund</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-6">
                                <h6>Budgeted</h6>
                                <h4 class="text-primary">$<?php echo number_format($adminBudgeted, 2); ?></h4>
                            </div>
                            <div class="col-6">
                                <h6>Actual</h6>
                                <h4 class="text-success">$<?php echo number_format($adminActual, 2); ?></h4>
                            </div>
                        </div>
                        <div class="progress mt-3">
                            <div class="progress-bar" role="progressbar" 
                                 style="width: <?php echo $adminBudgeted > 0 ? min(($adminActual / $adminBudgeted) * 100, 100) : 0; ?>%">
                                <?php echo $adminBudgeted > 0 ? round(($adminActual / $adminBudgeted) * 100) : 0; ?>%
                            </div>
                        </div>
                        <small class="text-muted">Funds for day-to-day operations and maintenance</small>
                    </div>
                </div>
            </div>

            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="mb-0">🏗️ Capital Works Fund</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-6">
                                <h6>Budgeted</h6>
                                <h4 class="text-warning">$<?php echo number_format($capitalBudgeted, 2); ?></h4>
                            </div>
                            <div class="col-6">
                                <h6>Actual</h6>
                                <h4 class="text-success">$<?php echo number_format($capitalActual, 2); ?></h4>
                            </div>
                        </div>
                        <div class="progress mt-3">
                            <div class="progress-bar bg-warning" role="progressbar" 
                                 style="width: <?php echo $capitalBudgeted > 0 ? min(($capitalActual / $capitalBudgeted) * 100, 100) : 0; ?>%">
                                <?php echo $capitalBudgeted > 0 ? round(($capitalActual / $capitalBudgeted) * 100) : 0; ?>%
                            </div>
                        </div>
                        <small class="text-muted">Funds for major repairs and improvements</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add Budget Item Form -->
        <?php if (hasRole('admin')): ?>
        <div class="card mb-4">
            <div class="card-header">
                <h5>Add Budget Item</h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <input type="hidden" name="action" value="add_budget_item">
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="fund_type" class="form-label">Fund Type *</label>
                                <select class="form-select" id="fund_type" name="fund_type" required>
                                    <option value="">Select fund type</option>
                                    <option value="administration">Administration Fund</option>
                                    <option value="capital_works">Capital Works Fund</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="category" class="form-label">Category *</label>
                                <input type="text" class="form-control" id="category" name="category" 
                                       placeholder="e.g., Insurance, Maintenance, Utilities" required>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="description" class="form-label">Description *</label>
                        <textarea class="form-control" id="description" name="description" rows="2" 
                                  placeholder="Detailed description of the budget item" required></textarea>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label for="budgeted_amount" class="form-label">Budgeted Amount *</label>
                                <div class="input-group">
                                    <span class="input-group-text">$</span>
                                    <input type="number" class="form-control" id="budgeted_amount" name="budgeted_amount" 
                                           step="0.01" min="0" required>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label for="actual_amount" class="form-label">Actual Amount</label>
                                <div class="input-group">
                                    <span class="input-group-text">$</span>
                                    <input type="number" class="form-control" id="actual_amount" name="actual_amount" 
                                           step="0.01" min="0" value="0">
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label for="financial_year" class="form-label">Financial Year</label>
                                <input type="text" class="form-control" id="financial_year" name="financial_year" 
                                       value="<?php echo htmlspecialchars($currentFinancialYear); ?>" readonly>
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Add Budget Item</button>
                </form>
            </div>
        </div>
        <?php endif; ?>

        <!-- Budget Items Tables -->
        <div class="row">
            <!-- Administration Fund Items -->
            <div class="col-lg-6 mb-4">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">Administration Fund Items</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-sm mb-0">
                                <thead>
                                    <tr>
                                        <th>Category</th>
                                        <th>Budgeted</th>
                                        <th>Actual</th>
                                        <th>%</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php 
                                    $adminItems = array_filter($budgetItems, fn($item) => $item['fund_type'] === 'administration');
                                    foreach ($adminItems as $item): 
                                        $percentage = $item['budgeted_amount'] > 0 ? ($item['actual_amount'] / $item['budgeted_amount']) * 100 : 0;
                                    ?>
                                        <tr>
                                            <td>
                                                <strong><?php echo htmlspecialchars($item['category']); ?></strong><br>
                                                <small class="text-muted"><?php echo htmlspecialchars($item['description']); ?></small>
                                            </td>
                                            <td>$<?php echo number_format($item['budgeted_amount'], 0); ?></td>
                                            <td>$<?php echo number_format($item['actual_amount'], 0); ?></td>
                                            <td>
                                                <span class="badge bg-<?php echo $percentage > 100 ? 'danger' : ($percentage > 80 ? 'warning' : 'success'); ?>">
                                                    <?php echo round($percentage); ?>%
                                                </span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                    <?php if (empty($adminItems)): ?>
                                        <tr>
                                            <td colspan="4" class="text-center text-muted py-3">No administration fund items found</td>
                                        </tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Capital Works Fund Items -->
            <div class="col-lg-6 mb-4">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="mb-0">Capital Works Fund Items</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-sm mb-0">
                                <thead>
                                    <tr>
                                        <th>Category</th>
                                        <th>Budgeted</th>
                                        <th>Actual</th>
                                        <th>%</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php 
                                    $capitalItems = array_filter($budgetItems, fn($item) => $item['fund_type'] === 'capital_works');
                                    foreach ($capitalItems as $item): 
                                        $percentage = $item['budgeted_amount'] > 0 ? ($item['actual_amount'] / $item['budgeted_amount']) * 100 : 0;
                                    ?>
                                        <tr>
                                            <td>
                                                <strong><?php echo htmlspecialchars($item['category']); ?></strong><br>
                                                <small class="text-muted"><?php echo htmlspecialchars($item['description']); ?></small>
                                            </td>
                                            <td>$<?php echo number_format($item['budgeted_amount'], 0); ?></td>
                                            <td>$<?php echo number_format($item['actual_amount'], 0); ?></td>
                                            <td>
                                                <span class="badge bg-<?php echo $percentage > 100 ? 'danger' : ($percentage > 80 ? 'warning' : 'success'); ?>">
                                                    <?php echo round($percentage); ?>%
                                                </span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                    <?php if (empty($capitalItems)): ?>
                                        <tr>
                                            <td colspan="4" class="text-center text-muted py-3">No capital works fund items found</td>
                                        </tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Levy Calculation Information -->
        <div class="card">
            <div class="card-header">
                <h5>💰 Levy Calculation Information</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <h6>Total Budget Requirements</h6>
                        <p><strong>Administration Fund:</strong> $<?php echo number_format($adminBudgeted, 2); ?></p>
                        <p><strong>Capital Works Fund:</strong> $<?php echo number_format($capitalBudgeted, 2); ?></p>
                        <p><strong>Total Annual Budget:</strong> $<?php echo number_format($adminBudgeted + $capitalBudgeted, 2); ?></p>
                    </div>
                    <div class="col-md-4">
                        <h6>Unit Entitlements</h6>
                        <p><strong>Total Entitlements:</strong> 200</p>
                        <p><strong>1 Bedroom Units:</strong> 1 entitlement</p>
                        <p><strong>2 Bedroom Units:</strong> 2 entitlements</p>
                        <p><strong>3 Bedroom Units:</strong> 3 entitlements</p>
                    </div>
                    <div class="col-md-4">
                        <h6>Quarterly Levy Rates</h6>
                        <?php 
                        $totalBudget = $adminBudgeted + $capitalBudgeted;
                        $quarterlyPerEntitlement = $totalBudget > 0 ? ($totalBudget / 4) / 200 : 0;
                        ?>
                        <p><strong>Per Entitlement:</strong> $<?php echo number_format($quarterlyPerEntitlement, 2); ?></p>
                        <p><strong>1 Bedroom:</strong> $<?php echo number_format($quarterlyPerEntitlement * 1, 2); ?></p>
                        <p><strong>2 Bedroom:</strong> $<?php echo number_format($quarterlyPerEntitlement * 2, 2); ?></p>
                        <p><strong>3 Bedroom:</strong> $<?php echo number_format($quarterlyPerEntitlement * 3, 2); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <div class="mt-4">
            <a href="/api/index.php" class="btn btn-secondary">Back to Dashboard</a>
            <a href="/api/pages/levies.php" class="btn btn-primary">View Levy Management</a>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 