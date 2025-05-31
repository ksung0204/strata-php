<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

// Require authentication and appropriate role
requireRole(['owner', 'committee', 'admin']);

$currentUser = getCurrentUser();

try {
    // Get owners data based on user role
    if (hasRole('admin')) {
        // Admins can see all owners with detailed info
        $stmt = $pdo->query('
            SELECT u.id, u.username, u.email, u.role, u.created_at,
                   un.unit_number, un.floor_number, un.unit_entitlements
            FROM users u 
            LEFT JOIN units un ON u.id = un.owner_id 
            WHERE u.role IN ("owner", "committee", "admin")
            ORDER BY u.role, u.username
        ');
    } elseif (hasRole('committee')) {
        // Committee can see owner names and unit info but not emails
        $stmt = $pdo->query('
            SELECT u.id, u.username, u.role,
                   un.unit_number, un.floor_number, un.unit_entitlements
            FROM users u 
            LEFT JOIN units un ON u.id = un.owner_id 
            WHERE u.role = "owner"
            ORDER BY u.username
        ');
    } else {
        // Owners can only see basic directory (names and unit numbers)
        $stmt = $pdo->query('
            SELECT u.id, u.username,
                   un.unit_number, un.floor_number
            FROM users u 
            LEFT JOIN units un ON u.id = un.owner_id 
            WHERE u.role = "owner"
            ORDER BY un.unit_number
        ');
    }
    
    $owners = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log('Owners page error: ' . $e->getMessage());
    $owners = [];
    $error = 'Unable to load owners data.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Owners Directory - Strata Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/api/index.php">Strata Management</a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, <?php echo htmlspecialchars($currentUser['username']); ?> (<?php echo htmlspecialchars(ucfirst($currentUser['role'])); ?>)</span>
                <a class="nav-link" href="/api/logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h1>Owners Directory</h1>
                <p class="text-muted mb-4">
                    <?php if (hasRole('admin')): ?>
                        Administrative view: All user details
                    <?php elseif (hasRole('committee')): ?>
                        Committee view: Owner contact information
                    <?php else: ?>
                        Directory of property owners
                    <?php endif; ?>
                </p>

                <?php if (isset($error)): ?>
                    <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>

                <?php if (empty($owners)): ?>
                    <div class="alert alert-info">No owners found in the system.</div>
                <?php else: ?>
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">
                                <?php if (hasRole('admin')): ?>
                                    Complete Strata Roll - Administrative View
                                <?php elseif (hasRole('committee')): ?>
                                    Strata Roll - Committee View
                                <?php else: ?>
                                    Owners Directory
                                <?php endif; ?>
                            </h5>
                            <small class="text-muted">
                                <?php if (hasAnyRole(['admin', 'committee'])): ?>
                                    Total Units: <?php echo count($owners); ?> | Total Entitlements: 
                                    <?php 
                                    $totalEntitlements = 0;
                                    foreach ($owners as $owner) {
                                        $totalEntitlements += $owner['unit_entitlements'] ?? 0;
                                    }
                                    echo $totalEntitlements;
                                    ?>
                                <?php else: ?>
                                    Building directory for <?php echo count($owners); ?> units
                                <?php endif; ?>
                            </small>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>Unit</th>
                                            <th>Floor</th>
                                            <th>Owner Name</th>
                                            <?php if (hasRole('admin')): ?>
                                                <th>Email</th>
                                                <th>Role</th>
                                                <th>Member Since</th>
                                            <?php endif; ?>
                                            <?php if (hasAnyRole(['admin', 'committee'])): ?>
                                                <th>Entitlements</th>
                                                <th>Voting %</th>
                                            <?php endif; ?>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($owners as $owner): ?>
                                            <tr>
                                                <td>
                                                    <strong><?php echo htmlspecialchars($owner['unit_number'] ?? 'N/A'); ?></strong>
                                                </td>
                                                <td><?php echo htmlspecialchars($owner['floor_number'] ?? 'N/A'); ?></td>
                                                <td>
                                                    <?php echo htmlspecialchars($owner['username']); ?>
                                                    <?php if ($owner['role'] === 'committee'): ?>
                                                        <span class="badge bg-warning text-dark">Committee</span>
                                                    <?php elseif ($owner['role'] === 'admin'): ?>
                                                        <span class="badge bg-danger">Admin</span>
                                                    <?php endif; ?>
                                                </td>
                                                <?php if (hasRole('admin')): ?>
                                                    <td><?php echo htmlspecialchars($owner['email'] ?? 'N/A'); ?></td>
                                                    <td>
                                                        <span class="badge bg-<?php 
                                                            echo $owner['role'] === 'admin' ? 'danger' : 
                                                                ($owner['role'] === 'committee' ? 'warning' : 'primary'); 
                                                        ?>">
                                                            <?php echo htmlspecialchars(ucfirst($owner['role'])); ?>
                                                        </span>
                                                    </td>
                                                    <td><?php echo htmlspecialchars(date('M d, Y', strtotime($owner['created_at']))); ?></td>
                                                <?php endif; ?>
                                                <?php if (hasAnyRole(['admin', 'committee'])): ?>
                                                    <td>
                                                        <strong><?php echo htmlspecialchars($owner['unit_entitlements'] ?? 'N/A'); ?></strong>
                                                    </td>
                                                    <td>
                                                        <?php 
                                                        $votingPercentage = $totalEntitlements > 0 && $owner['unit_entitlements'] 
                                                            ? round(($owner['unit_entitlements'] / $totalEntitlements) * 100, 2) 
                                                            : 0;
                                                        ?>
                                                        <?php echo $votingPercentage; ?>%
                                                    </td>
                                                <?php endif; ?>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Entitlements Summary -->
                    <?php if (hasAnyRole(['admin', 'committee'])): ?>
                    <div class="row mt-4">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h6>Unit Entitlements Summary</h6>
                                </div>
                                <div class="card-body">
                                    <?php
                                    $entitlementGroups = [];
                                    foreach ($owners as $owner) {
                                        $entitlements = $owner['unit_entitlements'] ?? 0;
                                        if (!isset($entitlementGroups[$entitlements])) {
                                            $entitlementGroups[$entitlements] = 0;
                                        }
                                        $entitlementGroups[$entitlements]++;
                                    }
                                    ksort($entitlementGroups);
                                    ?>
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>Entitlements</th>
                                                <th>Units</th>
                                                <th>Total Votes</th>
                                                <th>% of Total</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($entitlementGroups as $entitlement => $count): ?>
                                                <?php 
                                                $totalVotes = $entitlement * $count;
                                                $percentage = $totalEntitlements > 0 ? round(($totalVotes / $totalEntitlements) * 100, 1) : 0;
                                                ?>
                                                <tr>
                                                    <td><?php echo $entitlement; ?></td>
                                                    <td><?php echo $count; ?></td>
                                                    <td><?php echo $totalVotes; ?></td>
                                                    <td><?php echo $percentage; ?>%</td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                        <tfoot>
                                            <tr class="table-primary">
                                                <th>Total</th>
                                                <th><?php echo count($owners); ?></th>
                                                <th><?php echo $totalEntitlements; ?></th>
                                                <th>100%</th>
                                            </tr>
                                        </tfoot>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h6>NSW Strata Information</h6>
                                </div>
                                <div class="card-body">
                                    <h6>Voting Requirements:</h6>
                                    <ul class="list-unstyled small">
                                        <li><strong>Ordinary Resolution:</strong> More than 50% of votes</li>
                                        <li><strong>Special Resolution:</strong> At least 75% of votes</li>
                                        <li><strong>Unanimous Resolution:</strong> 100% of votes</li>
                                    </ul>
                                    
                                    <h6>Key Thresholds:</h6>
                                    <ul class="list-unstyled small">
                                        <li><strong>50% + 1 vote:</strong> <?php echo floor($totalEntitlements / 2) + 1; ?> votes</li>
                                        <li><strong>75% threshold:</strong> <?php echo ceil($totalEntitlements * 0.75); ?> votes</li>
                                        <li><strong>Quorum (25%):</strong> <?php echo ceil($totalEntitlements * 0.25); ?> votes</li>
                                    </ul>

                                    <div class="alert alert-info small">
                                        <strong>Note:</strong> Unit entitlements determine both voting rights and levy contributions according to NSW Strata Schemes Management Act 2015.
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                <?php endif; ?>

                <div class="mt-4">
                    <a href="/api/index.php" class="btn btn-secondary">Back to Dashboard</a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 