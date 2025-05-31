<?php
// Database initialization script
require_once __DIR__ . '/config.php';

try {
    echo "Initializing database with sample data...\n";

    // Hash passwords properly
    $adminPassword = password_hash('admin123', PASSWORD_ARGON2ID);
    $userPassword = password_hash('user123', PASSWORD_ARGON2ID);

    // Create tables and insert data
    
    // Clear existing data (for reset)
    $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
    $tables = ['levy_payments', 'levies', 'budget_items', 'maintenance_requests', 'documents', 'notices', 'updates', 'units', 'users'];
    foreach ($tables as $table) {
        $pdo->exec("DELETE FROM $table");
        $pdo->exec("ALTER TABLE $table AUTO_INCREMENT = 1");
    }
    $pdo->exec('SET FOREIGN_KEY_CHECKS = 1');

    // Insert users with properly hashed passwords
    $stmt = $pdo->prepare('INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)');
    $users = [
        [1, 'admin', 'admin@skylineapts.com.au', $adminPassword, 'admin'],
        [2, 'committee_chair', 'chair@skylineapts.com.au', $userPassword, 'committee'],
        [3, 'treasurer', 'treasurer@skylineapts.com.au', $userPassword, 'committee'],
        [4, 'john_smith', 'john.smith@email.com', $userPassword, 'owner'],
        [5, 'jane_doe', 'jane.doe@email.com', $userPassword, 'owner'],
        [6, 'mike_johnson', 'mike.johnson@email.com', $userPassword, 'owner'],
        [7, 'sarah_wilson', 'sarah.wilson@email.com', $userPassword, 'owner'],
        [8, 'david_brown', 'david.brown@email.com', $userPassword, 'owner'],
        [9, 'lisa_garcia', 'lisa.garcia@email.com', $userPassword, 'owner']
    ];

    foreach ($users as $user) {
        $stmt->execute($user);
    }
    echo "✓ Users created\n";

    // Insert units
    $stmt = $pdo->prepare('INSERT INTO units (id, unit_number, floor_number, unit_entitlements, owner_id) VALUES (?, ?, ?, ?, ?)');
    $units = [
        [1, '101', 1, 1, 4], [2, '102', 1, 1, 5], [3, '103', 1, 1, 6], [4, '104', 1, 1, 7],
        [5, '201', 2, 2, 8], [6, '202', 2, 2, 9], [7, '203', 2, 2, 4], [8, '204', 2, 2, 5],
        [9, '301', 3, 3, 6], [10, '302', 3, 3, 7], [11, '401', 4, 1, 8], [12, '402', 4, 1, 9],
        [13, '501', 5, 2, 4], [14, '502', 5, 2, 5], [15, '601', 6, 3, 6], [16, '602', 6, 3, 7]
    ];

    foreach ($units as $unit) {
        $stmt->execute($unit);
    }
    echo "✓ Units created\n";

    // Insert maintenance requests
    $stmt = $pdo->prepare('INSERT INTO maintenance_requests (id, unit_id, title, description, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
    $requests = [
        [1, 1, 'Leaking tap in bathroom', 'The bathroom tap is constantly dripping and needs repair.', 'pending', 4, '2024-01-15 10:00:00'],
        [2, NULL, 'Elevator making strange noises', 'The elevator is making unusual noises when moving between floors.', 'in_progress', 5, '2024-01-10 14:30:00'],
        [3, NULL, 'Broken light in parking garage', 'Light fixture in parking space B15 is not working.', 'completed', 6, '2024-01-05 16:45:00'],
        [4, 5, 'Air conditioning not working', 'Unit AC system stopped working yesterday evening.', 'pending', 8, '2024-01-20 09:15:00'],
        [5, NULL, 'Pool filter needs cleaning', 'Rooftop pool water is becoming cloudy.', 'in_progress', 2, '2024-01-18 11:30:00']
    ];

    foreach ($requests as $request) {
        $stmt->execute($request);
    }
    echo "✓ Maintenance requests created\n";

    // Insert documents
    $stmt = $pdo->prepare('INSERT INTO documents (id, title, file_path, document_type, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?)');
    $documents = [
        [1, 'Building Insurance Certificate 2024', '/documents/insurance_2024.pdf', 'insurance', 1, '2024-01-15 10:00:00'],
        [2, 'Annual Financial Report 2023', '/documents/financial_report_2023.pdf', 'financial', 3, '2024-01-10 14:30:00'],
        [3, 'AGM Minutes - December 2023', '/documents/agm_minutes_dec2023.pdf', 'minutes', 2, '2023-12-15 18:00:00'],
        [4, 'Building Bylaws and Regulations', '/documents/bylaws_2024.pdf', 'other', 1, '2024-01-01 09:00:00'],
        [5, 'Capital Works Plan 2024-2026', '/documents/capital_works_plan.pdf', 'other', 2, '2024-01-05 15:20:00'],
        [6, 'Quarterly Budget Report Q1 2024', '/documents/budget_q1_2024.pdf', 'financial', 3, '2024-01-25 16:45:00']
    ];

    foreach ($documents as $document) {
        $stmt->execute($document);
    }
    echo "✓ Documents created\n";

    // Insert levies
    $stmt = $pdo->prepare('INSERT INTO levies (id, unit_id, amount, due_date, status, quarter, admin_amount, capital_amount, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $levies = [
        [1, 1, 212.50, '2024-02-15', 'pending', 'Q1 2024', 106.25, 106.25, 1, '2024-01-15 10:00:00'],
        [2, 2, 212.50, '2024-02-15', 'paid', 'Q1 2024', 106.25, 106.25, 1, '2024-01-15 10:00:00'],
        [3, 3, 212.50, '2024-01-15', 'overdue', 'Q4 2023', 106.25, 106.25, 1, '2023-12-15 10:00:00'],
        [4, 4, 212.50, '2024-03-15', 'pending', 'Q1 2024', 106.25, 106.25, 1, '2024-02-15 10:00:00'],
        [5, 5, 425.00, '2024-02-15', 'pending', 'Q1 2024', 212.50, 212.50, 1, '2024-01-15 10:00:00'],
        [6, 6, 425.00, '2024-02-15', 'paid', 'Q1 2024', 212.50, 212.50, 1, '2024-01-15 10:00:00'],
        [7, 9, 637.50, '2024-02-15', 'pending', 'Q1 2024', 318.75, 318.75, 1, '2024-01-15 10:00:00'],
        [8, 10, 637.50, '2024-01-15', 'overdue', 'Q4 2023', 318.75, 318.75, 1, '2023-12-15 10:00:00']
    ];

    foreach ($levies as $levy) {
        $stmt->execute($levy);
    }
    echo "✓ Levies created\n";

    // Get current financial year
    $currentFinancialYear = (date('m') >= 7) ? date('Y') . '-' . (date('Y') + 1) : (date('Y') - 1) . '-' . date('Y');

    // Insert budget items
    $stmt = $pdo->prepare('INSERT INTO budget_items (id, category, description, budgeted_amount, actual_amount, fund_type, financial_year, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $budgetItems = [
        [1, 'Insurance', 'Building insurance premium', 45000.00, 44500.00, 'administration', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [2, 'Maintenance', 'General building maintenance', 25000.00, 18750.00, 'administration', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [3, 'Utilities', 'Electricity and water for common areas', 15000.00, 12500.00, 'administration', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [4, 'Management Fees', 'Strata management company fees', 24000.00, 6000.00, 'administration', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [5, 'Cleaning', 'Common area cleaning services', 18000.00, 4500.00, 'administration', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [6, 'Security', '24/7 security monitoring', 12000.00, 3000.00, 'administration', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [7, 'Lift Upgrade', 'Replacement of lift systems', 150000.00, 75000.00, 'capital_works', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [8, 'Roof Repairs', 'Major roof waterproofing', 80000.00, 0.00, 'capital_works', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [9, 'Pool Renovation', 'Rooftop pool area improvements', 45000.00, 12000.00, 'capital_works', $currentFinancialYear, 1, '2024-01-01 09:00:00'],
        [10, 'Fire Safety Upgrade', 'Updated fire safety systems', 35000.00, 0.00, 'capital_works', $currentFinancialYear, 1, '2024-01-01 09:00:00']
    ];

    foreach ($budgetItems as $item) {
        $stmt->execute($item);
    }
    echo "✓ Budget items created\n";

    // Insert levy payments
    $stmt = $pdo->prepare('INSERT INTO levy_payments (id, levy_id, amount, payment_date, payment_method, reference_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
    $payments = [
        [1, 2, 212.50, '2024-01-20', 'credit_card', 'CC240120001', '2024-01-20 14:25:00'],
        [2, 6, 425.00, '2024-01-22', 'bank_transfer', 'BT240122001', '2024-01-22 10:15:00']
    ];

    foreach ($payments as $payment) {
        $stmt->execute($payment);
    }
    echo "✓ Levy payments created\n";

    // Insert notices
    $stmt = $pdo->prepare('INSERT INTO notices (id, title, content, is_important, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)');
    $notices = [
        [1, 'Pool Maintenance Schedule', 'The rooftop pool will be closed for maintenance on February 5-7, 2024.', FALSE, 2, '2024-01-25 10:00:00'],
        [2, 'Annual General Meeting Notice', 'The AGM will be held on March 15, 2024 at 7:00 PM in the community room.', TRUE, 2, '2024-01-20 09:30:00'],
        [3, 'Elevator Maintenance', 'Lift B will be out of service February 1-3 for scheduled maintenance.', FALSE, 1, '2024-01-18 14:45:00']
    ];

    foreach ($notices as $notice) {
        $stmt->execute($notice);
    }
    echo "✓ Notices created\n";

    // Insert updates
    $stmt = $pdo->prepare('INSERT INTO updates (id, title, content, created_by, created_at) VALUES (?, ?, ?, ?, ?)');
    $updates = [
        [1, 'New Security Features Installed', 'Enhanced CCTV system and new access cards have been installed throughout the building.', 1, '2024-01-20 16:30:00'],
        [2, 'Waste Management Changes', 'New recycling bins have been installed on each floor. Please separate recyclables accordingly.', 2, '2024-01-15 11:20:00'],
        [3, 'Building WiFi Upgrade', 'Common area WiFi has been upgraded to provide better coverage and speed.', 1, '2024-01-10 13:45:00']
    ];

    foreach ($updates as $update) {
        $stmt->execute($update);
    }
    echo "✓ Updates created\n";

    echo "\n✅ Database initialization completed successfully!\n";
    echo "\nLogin credentials:\n";
    echo "Admin: admin / admin123\n";
    echo "Committee: committee_chair / user123\n";
    echo "Owner: john_smith / user123\n";

} catch (PDOException $e) {
    echo "❌ Error initializing database: " . $e->getMessage() . "\n";
    exit(1);
}
?> 