<?php
require_once __DIR__ . '/database/config.php';
require_once __DIR__ . '/includes/session.php';

// Require authentication
requireLogin();

header('Content-Type: application/json');

try {
    // Get recent updates from the database
    $stmt = $pdo->query('SELECT * FROM updates ORDER BY created_at DESC LIMIT 5');
    $updates = $stmt->fetchAll();

    $html = '';
    if (empty($updates)) {
        $html = '<div class="text-muted">No recent updates available.</div>';
    } else {
        foreach ($updates as $update) {
            $html .= sprintf(
                '<div class="update-item mb-3 p-3 border rounded">
                    <h6 class="mb-2">%s</h6>
                    <p class="text-muted small mb-1">%s</p>
                    <small class="text-muted">Posted: %s</small>
                </div>',
                htmlspecialchars($update['title']),
                htmlspecialchars($update['content']),
                date('M d, Y', strtotime($update['created_at']))
            );
        }
    }

    echo json_encode(['success' => true, 'html' => $html]);
} catch (PDOException $e) {
    error_log('Updates error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Unable to load updates']);
}
?> 