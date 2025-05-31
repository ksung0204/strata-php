<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

// Require committee or admin access
requireRole(['committee', 'admin']);

$currentUser = getCurrentUser();
$error = '';
$success = '';

// Handle levy generation form submission (HTTP POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        if ($action === 'generate_levies') {
            $due_date = $_POST['due_date'] ?? '';
            $admin_amount_per_entitlement = floatval($_POST['admin_amount_per_entitlement'] ?? 0);
            $capital_amount_per_entitlement = floatval($_POST['capital_amount_per_entitlement'] ?? 0);
            $quarter = sanitizeInput($_POST['quarter'] ?? '');

            if (empty($due_date) || $admin_amount_per_entitlement <= 0 || $capital_amount_per_entitlement <= 0) {
                $error = 'Please fill in all required fields with valid amounts.';
            } else {
                try {
                    // Begin transaction
                    $pdo->beginTransaction();

                    // Get all units with their entitlements and owners
                    $stmt = $pdo->query('
                        SELECT u.id as unit_id, u.unit_number, u.unit_entitlements, u.owner_id, 
                               usr.username, usr.email 
                        FROM units u 
                        LEFT JOIN users usr ON u.owner_id = usr.id 
                        WHERE u.owner_id IS NOT NULL
                        ORDER BY u.unit_number
                    ');
                    $units = $stmt->fetchAll();

                    if (empty($units)) {
                        throw new Exception('No units with owners found. Please assign owners to units first.');
                    }

                    $leviesGenerated = 0;
                    foreach ($units as $unit) {
                        $totalAmount = ($admin_amount_per_entitlement + $capital_amount_per_entitlement) * $unit['unit_entitlements'];
                        
                        // Insert levy notice
                        $stmt = $pdo->prepare('
                            INSERT INTO levies 
                            (unit_id, amount, due_date, status, quarter, admin_amount, capital_amount, created_by) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ');
                        
                        $adminAmount = $admin_amount_per_entitlement * $unit['unit_entitlements'];
                        $capitalAmount = $capital_amount_per_entitlement * $unit['unit_entitlements'];
                        
                        // Add columns to levies table if they don't exist
                        try {
                            $pdo->exec("ALTER TABLE levies ADD COLUMN quarter VARCHAR(20)");
                        } catch (PDOException $e) {
                            // Column might already exist
                        }
                        try {
                            $pdo->exec("ALTER TABLE levies ADD COLUMN admin_amount DECIMAL(10,2)");
                        } catch (PDOException $e) {
                            // Column might already exist
                        }
                        try {
                            $pdo->exec("ALTER TABLE levies ADD COLUMN capital_amount DECIMAL(10,2)");
                        } catch (PDOException $e) {
                            // Column might already exist
                        }
                        try {
                            $pdo->exec("ALTER TABLE levies ADD COLUMN created_by INT");
                        } catch (PDOException $e) {
                            // Column might already exist
                        }

                        if ($stmt->execute([$unit['unit_id'], $totalAmount, $due_date, 'pending', $quarter, $adminAmount, $capitalAmount, $currentUser['id']])) {
                            $leviesGenerated++;
                        }
                    }

                    $pdo->commit();
                    $success = "Successfully generated $leviesGenerated levy notices for $quarter.";
                    
                } catch (Exception $e) {
                    $pdo->rollBack();
                    error_log('Levy generation error: ' . $e->getMessage());
                    $error = 'Error generating levies: ' . $e->getMessage();
                } catch (PDOException $e) {
                    $pdo->rollBack();
                    error_log('Levy generation database error: ' . $e->getMessage());
                    $error = 'Database error. Please try again.';
                }
            }
        }
    }
}

// Get budget data for calculations (HTTP GET)
try {
    // Get current financial year
    $currentFinancialYear = (date('m') >= 7) ? date('Y') . '-' . (date('Y') + 1) : (date('Y') - 1) . '-' . date('Y');
    
    // Get budget totals
    $stmt = $pdo->prepare('
        SELECT fund_type, SUM(budgeted_amount) as total_budgeted 
        FROM budget_items 
        WHERE financial_year = ? 
        GROUP BY fund_type
    ');
    $stmt->execute([$currentFinancialYear]);
    $budgetTotals = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

    $adminBudget = $budgetTotals['administration'] ?? 85000; // Default sample amounts
    $capitalBudget = $budgetTotals['capital_works'] ?? 230000;

    // Get units summary
    $stmt = $pdo->query('
        SELECT COUNT(*) as total_units, SUM(unit_entitlements) as total_entitlements 
        FROM units WHERE owner_id IS NOT NULL
    ');
    $unitsSummary = $stmt->fetch();
    
    if (!$unitsSummary || $unitsSummary['total_units'] == 0) {
        // Sample data if no units exist
        $unitsSummary = ['total_units' => 120, 'total_entitlements' => 200];
    }

    // Calculate suggested quarterly amounts per entitlement
    $quarterlyAdminPerEntitlement = $adminBudget / 4 / $unitsSummary['total_entitlements'];
    $quarterlyCapitalPerEntitlement = $capitalBudget / 4 / $unitsSummary['total_entitlements'];

    // Get recent levy generations
    $stmt = $pdo->query('
        SELECT quarter, due_date, COUNT(DISTINCT unit_id) as units_generated, 
               SUM(amount) as total_amount, MAX(created_at) as generated_at,
               u.username as generated_by
        FROM levies l 
        LEFT JOIN users u ON l.created_by = u.id 
        WHERE l.created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
        GROUP BY quarter, due_date, l.created_by
        ORDER BY l.created_at DESC
        LIMIT 10
    ');
    $recentGenerations = $stmt->fetchAll();

} catch (PDOException $e) {
    error_log('Budget/units retrieval error: ' . $e->getMessage());
    $adminBudget = 85000;
    $capitalBudget = 230000;
    $unitsSummary = ['total_units' => 120, 'total_entitlements' => 200];
    $quarterlyAdminPerEntitlement = $adminBudget / 4 / 200;
    $quarterlyCapitalPerEntitlement = $capitalBudget / 4 / 200;
    $recentGenerations = [];
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generate Levy Notices - Strata Management System</title>
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
        <h1>📋 Generate Levy Notices</h1>
        <p class="text-muted mb-4">Generate quarterly levy notices for all unit owners based on budget requirements and unit entitlements.</p>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <!-- Budget Overview -->
        <div class="row mb-4">
            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h6 class="mb-0">💼 Administration Fund</h6>
                    </div>
                    <div class="card-body">
                        <h4>$<?php echo number_format($adminBudget, 2); ?></h4>
                        <small class="text-muted">Annual budget</small>
                        <hr>
                        <p class="mb-0"><strong>Quarterly per entitlement:</strong><br>
                        $<?php echo number_format($quarterlyAdminPerEntitlement, 2); ?></p>
                    </div>
                </div>
            </div>

            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h6 class="mb-0">🏗️ Capital Works Fund</h6>
                    </div>
                    <div class="card-body">
                        <h4>$<?php echo number_format($capitalBudget, 2); ?></h4>
                        <small class="text-muted">Annual budget</small>
                        <hr>
                        <p class="mb-0"><strong>Quarterly per entitlement:</strong><br>
                        $<?php echo number_format($quarterlyCapitalPerEntitlement, 2); ?></p>
                    </div>
                </div>
            </div>

            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h6 class="mb-0">🏢 Units Summary</h6>
                    </div>
                    <div class="card-body">
                        <h4><?php echo $unitsSummary['total_units']; ?> Units</h4>
                        <small class="text-muted">Total units with owners</small>
                        <hr>
                        <p class="mb-0"><strong>Total entitlements:</strong><br>
                        <?php echo $unitsSummary['total_entitlements']; ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Levy Generation Form -->
        <div class="card mb-4">
            <div class="card-header">
                <h5>Generate New Levy Notices</h5>
            </div>
            <div class="card-body">
                <form method="POST" id="levyForm">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <input type="hidden" name="action" value="generate_levies">
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="quarter" class="form-label">Quarter *</label>
                                <select class="form-select" id="quarter" name="quarter" required>
                                    <option value="">Select quarter</option>
                                    <option value="Q1 <?php echo date('Y'); ?>">Q1 <?php echo date('Y'); ?> (Jan-Mar)</option>
                                    <option value="Q2 <?php echo date('Y'); ?>">Q2 <?php echo date('Y'); ?> (Apr-Jun)</option>
                                    <option value="Q3 <?php echo date('Y'); ?>">Q3 <?php echo date('Y'); ?> (Jul-Sep)</option>
                                    <option value="Q4 <?php echo date('Y'); ?>">Q4 <?php echo date('Y'); ?> (Oct-Dec)</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="due_date" class="form-label">Due Date *</label>
                                <input type="date" class="form-control" id="due_date" name="due_date" 
                                       min="<?php echo date('Y-m-d'); ?>" required>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="admin_amount_per_entitlement" class="form-label">Administration Fund (per entitlement) *</label>
                                <div class="input-group">
                                    <span class="input-group-text">$</span>
                                    <input type="number" class="form-control" id="admin_amount_per_entitlement" 
                                           name="admin_amount_per_entitlement" step="0.01" min="0" 
                                           value="<?php echo number_format($quarterlyAdminPerEntitlement, 2, '.', ''); ?>" required>
                                </div>
                                <small class="text-muted">Suggested: $<?php echo number_format($quarterlyAdminPerEntitlement, 2); ?></small>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="capital_amount_per_entitlement" class="form-label">Capital Works Fund (per entitlement) *</label>
                                <div class="input-group">
                                    <span class="input-group-text">$</span>
                                    <input type="number" class="form-control" id="capital_amount_per_entitlement" 
                                           name="capital_amount_per_entitlement" step="0.01" min="0" 
                                           value="<?php echo number_format($quarterlyCapitalPerEntitlement, 2, '.', ''); ?>" required>
                                </div>
                                <small class="text-muted">Suggested: $<?php echo number_format($quarterlyCapitalPerEntitlement, 2); ?></small>
                            </div>
                        </div>
                    </div>

                    <!-- Preview Calculations -->
                    <div class="card bg-light">
                        <div class="card-body">
                            <h6>Preview Levy Amounts:</h6>
                            <div class="row">
                                <div class="col-md-3">
                                    <strong>1 Bedroom (1 entitlement):</strong><br>
                                    <span id="preview_1bed">$<?php echo number_format($quarterlyAdminPerEntitlement + $quarterlyCapitalPerEntitlement, 2); ?></span>
                                </div>
                                <div class="col-md-3">
                                    <strong>2 Bedroom (2 entitlements):</strong><br>
                                    <span id="preview_2bed">$<?php echo number_format(($quarterlyAdminPerEntitlement + $quarterlyCapitalPerEntitlement) * 2, 2); ?></span>
                                </div>
                                <div class="col-md-3">
                                    <strong>3 Bedroom (3 entitlements):</strong><br>
                                    <span id="preview_3bed">$<?php echo number_format(($quarterlyAdminPerEntitlement + $quarterlyCapitalPerEntitlement) * 3, 2); ?></span>
                                </div>
                                <div class="col-md-3">
                                    <strong>Total Revenue:</strong><br>
                                    <span id="preview_total">$<?php echo number_format(($quarterlyAdminPerEntitlement + $quarterlyCapitalPerEntitlement) * $unitsSummary['total_entitlements'], 2); ?></span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-3">
                        <button type="submit" class="btn btn-primary" onclick="return confirm('Are you sure you want to generate levy notices for all units? This action cannot be undone.')">
                            Generate Levy Notices
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Recent Generations -->
        <?php if (!empty($recentGenerations)): ?>
        <div class="card">
            <div class="card-header">
                <h5>Recent Levy Generations</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Quarter</th>
                                <th>Due Date</th>
                                <th>Units</th>
                                <th>Total Amount</th>
                                <th>Generated By</th>
                                <th>Generated At</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recentGenerations as $generation): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($generation['quarter']); ?></td>
                                    <td><?php echo date('M d, Y', strtotime($generation['due_date'])); ?></td>
                                    <td><?php echo $generation['units_generated']; ?></td>
                                    <td>$<?php echo number_format($generation['total_amount'], 2); ?></td>
                                    <td><?php echo htmlspecialchars($generation['generated_by'] ?? 'System'); ?></td>
                                    <td><?php echo date('M d, Y g:i A', strtotime($generation['generated_at'])); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <div class="mt-4">
            <a href="/api/pages/budget.php" class="btn btn-secondary">Budget Management</a>
            <a href="/api/pages/levies.php" class="btn btn-primary">View Levies</a>
            <a href="/api/index.php" class="btn btn-outline-secondary">Back to Dashboard</a>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Update preview calculations when amounts change
        function updatePreview() {
            const adminAmount = parseFloat(document.getElementById('admin_amount_per_entitlement').value) || 0;
            const capitalAmount = parseFloat(document.getElementById('capital_amount_per_entitlement').value) || 0;
            const totalPerEntitlement = adminAmount + capitalAmount;
            
            document.getElementById('preview_1bed').textContent = '$' + (totalPerEntitlement * 1).toFixed(2);
            document.getElementById('preview_2bed').textContent = '$' + (totalPerEntitlement * 2).toFixed(2);
            document.getElementById('preview_3bed').textContent = '$' + (totalPerEntitlement * 3).toFixed(2);
            document.getElementById('preview_total').textContent = '$' + (totalPerEntitlement * <?php echo $unitsSummary['total_entitlements']; ?>).toFixed(2);
        }

        document.getElementById('admin_amount_per_entitlement').addEventListener('input', updatePreview);
        document.getElementById('capital_amount_per_entitlement').addEventListener('input', updatePreview);
    </script>
</body>
</html> 