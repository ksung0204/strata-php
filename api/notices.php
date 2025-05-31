<?php
require_once __DIR__ . '/database/config.php';
require_once __DIR__ . '/includes/session.php';

// Require authentication
requireLogin();

header('Content-Type: application/json');

try {
    // Get important notices from the database
    $stmt = $pdo->query('SELECT * FROM notices WHERE is_important = 1 ORDER BY created_at DESC LIMIT 3');
    $notices = $stmt->fetchAll();

    $html = '';
    if (empty($notices)) {
        $html = '<div class="text-muted">No important notices at this time.</div>';
    } else {
        foreach ($notices as $notice) {
            $html .= sprintf(
                '<div class="notice-item mb-3 p-3 border-start border-4 border-danger bg-light">
                    <h6 class="text-danger mb-2">%s</h6>
                    <p class="small mb-1">%s</p>
                    <small class="text-muted">Posted: %s</small>
                </div>',
                htmlspecialchars($notice['title']),
                htmlspecialchars($notice['content']),
                date('M d, Y', strtotime($notice['created_at']))
            );
        }
    }

    echo json_encode(['success' => true, 'html' => $html]);
} catch (PDOException $e) {
    error_log('Notices error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Unable to load notices']);
}
?> 