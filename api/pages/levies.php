<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

// Require authentication
requireLogin();

$currentUser = getCurrentUser();
$error = '';
$success = '';

// Handle levy payment (HTTP POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        if ($action === 'pay_levy') {
            $levy_id = intval($_POST['levy_id'] ?? 0);
            $payment_method = sanitizeInput($_POST['payment_method'] ?? '');
            $amount = floatval($_POST['amount'] ?? 0);

            if ($levy_id <= 0 || empty($payment_method) || $amount <= 0) {
                $error = 'Please fill in all required fields with valid values.';
            } else {
                try {
                    // Verify the levy belongs to current user (unless admin/committee)
                    if (!hasAnyRole(['admin', 'committee'])) {
                        $stmt = $pdo->prepare('
                            SELECT l.* FROM levies l 
                            JOIN units u ON l.unit_id = u.id 
                            WHERE l.id = ? AND u.owner_id = ?
                        ');
                        $stmt->execute([$levy_id, $currentUser['id']]);
                        $levy = $stmt->fetch();
                        
                        if (!$levy) {
                            $error = 'Levy not found or you do not have permission to pay it.';
                        }
                    } else {
                        $stmt = $pdo->prepare('SELECT * FROM levies WHERE id = ?');
                        $stmt->execute([$levy_id]);
                        $levy = $stmt->fetch();
                    }

                    if (!isset($error) && $levy) {
                        $pdo->beginTransaction();
                        
                        // Generate reference number
                        $reference = strtoupper($payment_method[0] . $payment_method[1]) . date('ymdHis');
                        
                        // Insert payment record
                        $stmt = $pdo->prepare('
                            INSERT INTO levy_payments (levy_id, amount, payment_date, payment_method, reference_number) 
                            VALUES (?, ?, CURDATE(), ?, ?)
                        ');
                        $stmt->execute([$levy_id, $amount, $payment_method, $reference]);
                        
                        // Update levy status to paid
                        $stmt = $pdo->prepare('UPDATE levies SET status = ? WHERE id = ?');
                        $stmt->execute(['paid', $levy_id]);
                        
                        $pdo->commit();
                        $success = "Payment of $" . number_format($amount, 2) . " processed successfully! Reference: " . $reference;
                    }
                } catch (PDOException $e) {
                    $pdo->rollBack();
                    error_log('Levy payment error: ' . $e->getMessage());
                    $error = 'Payment processing failed. Please try again.';
                }
            }
        }
    }
}

// Get levies data (HTTP GET)
try {
    if (hasRole('admin') || hasRole('committee')) {
        // Admins and committee can see all levies
        $stmt = $pdo->query('
            SELECT l.*, u.username as owner_name, un.unit_number 
            FROM levies l 
            LEFT JOIN units un ON l.unit_id = un.id 
            LEFT JOIN users u ON un.owner_id = u.id 
            ORDER BY l.due_date DESC
        ');
    } else {
        // Owners can only see their own levies
        $stmt = $pdo->prepare('
            SELECT l.*, u.username as owner_name, un.unit_number 
            FROM levies l 
            LEFT JOIN units un ON l.unit_id = un.id 
            LEFT JOIN users u ON un.owner_id = u.id 
            WHERE un.owner_id = ?
            ORDER BY l.due_date DESC
        ');
        $stmt->execute([$currentUser['id']]);
    }
    
    $levies = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log('Levies page error: ' . $e->getMessage());
    $levies = [];
    $error = 'Unable to load levy information.';
}

function getStatusBadge($status) {
    switch ($status) {
        case 'pending': return 'bg-warning text-dark';
        case 'paid': return 'bg-success';
        case 'overdue': return 'bg-danger';
        default: return 'bg-secondary';
    }
}

function getDaysUntilDue($dueDate) {
    $today = new DateTime();
    $due = new DateTime($dueDate);
    $diff = $today->diff($due);
    
    if ($due < $today) {
        return -$diff->days; // Negative for overdue
    } else {
        return $diff->days; // Positive for days remaining
    }
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Levies - Strata Management System</title>
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
        <h1>💰 Levy Management</h1>
        <p class="text-muted mb-4">
            <?php echo hasAnyRole(['admin', 'committee']) ? 'Manage strata levies and payments for all units.' : 'View and pay your strata levies.'; ?>
        </p>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <!-- Levy Summary Cards -->
        <div class="row mb-4">
            <?php
            $totalPending = 0;
            $totalOverdue = 0;
            $totalPaid = 0;
            
            foreach ($levies as $levy) {
                switch ($levy['status']) {
                    case 'pending':
                        $totalPending += $levy['amount'];
                        break;
                    case 'overdue':
                        $totalOverdue += $levy['amount'];
                        break;
                    case 'paid':
                        $totalPaid += $levy['amount'];
                        break;
                }
            }
            ?>
            
            <div class="col-md-4">
                <div class="card bg-warning bg-opacity-25">
                    <div class="card-body text-center">
                        <h4 class="text-warning">$<?php echo number_format($totalPending, 2); ?></h4>
                        <p class="mb-0">Pending Payments</p>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card bg-danger bg-opacity-25">
                    <div class="card-body text-center">
                        <h4 class="text-danger">$<?php echo number_format($totalOverdue, 2); ?></h4>
                        <p class="mb-0">Overdue Payments</p>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card bg-success bg-opacity-25">
                    <div class="card-body text-center">
                        <h4 class="text-success">$<?php echo number_format($totalPaid, 2); ?></h4>
                        <p class="mb-0">Paid This Period</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Levies Table -->
        <div class="card">
            <div class="card-header">
                <h5>
                    <?php echo hasAnyRole(['admin', 'committee']) ? 'All Levy Notices' : 'Your Levy Notices'; ?>
                </h5>
            </div>
            <div class="card-body">
                <?php if (empty($levies)): ?>
                    <div class="text-center text-muted py-4">
                        <p>No levy notices found.</p>
                        <?php if (hasAnyRole(['admin', 'committee'])): ?>
                            <p><a href="/api/pages/generate_levies.php" class="btn btn-primary">Generate Levy Notices</a></p>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <?php if (hasAnyRole(['admin', 'committee'])): ?>
                                        <th>Unit</th>
                                        <th>Owner</th>
                                    <?php endif; ?>
                                    <th>Amount</th>
                                    <th>Due Date</th>
                                    <th>Quarter</th>
                                    <th>Status</th>
                                    <th>Days</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($levies as $levy): 
                                    $daysUntilDue = getDaysUntilDue($levy['due_date']);
                                ?>
                                    <tr>
                                        <?php if (hasAnyRole(['admin', 'committee'])): ?>
                                            <td><strong><?php echo htmlspecialchars($levy['unit_number'] ?? 'N/A'); ?></strong></td>
                                            <td><?php echo htmlspecialchars($levy['owner_name'] ?? 'Unassigned'); ?></td>
                                        <?php endif; ?>
                                        <td>
                                            <strong>$<?php echo number_format($levy['amount'], 2); ?></strong>
                                            <?php if ($levy['admin_amount'] && $levy['capital_amount']): ?>
                                                <br><small class="text-muted">
                                                    Admin: $<?php echo number_format($levy['admin_amount'], 2); ?> | 
                                                    Capital: $<?php echo number_format($levy['capital_amount'], 2); ?>
                                                </small>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo date('M d, Y', strtotime($levy['due_date'])); ?></td>
                                        <td><?php echo htmlspecialchars($levy['quarter'] ?? 'N/A'); ?></td>
                                        <td>
                                            <span class="badge <?php echo getStatusBadge($levy['status']); ?>">
                                                <?php echo ucfirst(htmlspecialchars($levy['status'])); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if ($daysUntilDue < 0): ?>
                                                <span class="text-danger"><?php echo abs($daysUntilDue); ?> days overdue</span>
                                            <?php elseif ($daysUntilDue == 0): ?>
                                                <span class="text-warning">Due today</span>
                                            <?php else: ?>
                                                <span class="text-muted"><?php echo $daysUntilDue; ?> days</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ($levy['status'] === 'pending' || $levy['status'] === 'overdue'): ?>
                                                <button class="btn btn-sm btn-primary" data-bs-toggle="modal" 
                                                        data-bs-target="#paymentModal" 
                                                        data-levy-id="<?php echo $levy['id']; ?>"
                                                        data-amount="<?php echo $levy['amount']; ?>"
                                                        data-unit="<?php echo htmlspecialchars($levy['unit_number'] ?? 'Your Unit'); ?>">
                                                    Pay Now
                                                </button>
                                            <?php elseif ($levy['status'] === 'paid'): ?>
                                                <span class="text-success small">✓ Paid</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="mt-4">
            <a href="/api/index.php" class="btn btn-secondary">Back to Dashboard</a>
            <?php if (hasAnyRole(['admin', 'committee'])): ?>
                <a href="/api/pages/generate_levies.php" class="btn btn-primary">Generate New Levies</a>
            <?php endif; ?>
        </div>
    </div>

    <!-- Payment Modal -->
    <div class="modal fade" id="paymentModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Pay Levy Notice</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                        <input type="hidden" name="action" value="pay_levy">
                        <input type="hidden" name="levy_id" id="modal_levy_id">
                        
                        <div class="mb-3">
                            <label class="form-label">Unit:</label>
                            <span id="modal_unit" class="fw-bold"></span>
                        </div>
                        
                        <div class="mb-3">
                            <label for="amount" class="form-label">Amount *</label>
                            <div class="input-group">
                                <span class="input-group-text">$</span>
                                <input type="number" class="form-control" name="amount" id="modal_amount" 
                                       step="0.01" min="0" readonly>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="payment_method" class="form-label">Payment Method *</label>
                            <select class="form-select" name="payment_method" required>
                                <option value="">Select payment method</option>
                                <option value="credit_card">Credit Card</option>
                                <option value="bank_transfer">Bank Transfer</option>
                                <option value="cheque">Cheque</option>
                            </select>
                        </div>
                        
                        <div class="alert alert-info small">
                            <strong>Note:</strong> This is a simulated payment system. In a real implementation, 
                            you would integrate with a payment gateway like Stripe or PayPal.
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Process Payment</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Handle payment modal data
        document.getElementById('paymentModal').addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const levyId = button.getAttribute('data-levy-id');
            const amount = button.getAttribute('data-amount');
            const unit = button.getAttribute('data-unit');
            
            document.getElementById('modal_levy_id').value = levyId;
            document.getElementById('modal_amount').value = amount;
            document.getElementById('modal_unit').textContent = unit;
        });
    </script>
</body>
</html> 