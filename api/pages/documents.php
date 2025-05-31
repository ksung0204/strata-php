<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../database/config.php';

// Require authentication
requireLogin();

$currentUser = getCurrentUser();
$error = '';
$success = '';

// Handle document upload (HTTP POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && hasAnyRole(['admin', 'committee'])) {
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        if ($action === 'upload_document') {
            $title = sanitizeInput($_POST['title'] ?? '');
            $document_type = sanitizeInput($_POST['document_type'] ?? '');
            $description = sanitizeInput($_POST['description'] ?? '');

            if (empty($title) || empty($document_type)) {
                $error = 'Please fill in all required fields.';
            } else {
                try {
                    // For demo purposes, we'll create a placeholder file path
                    // In a real implementation, you'd handle file upload here
                    $file_path = '/documents/' . strtolower(str_replace(' ', '_', $title)) . '.pdf';
                    
                    $stmt = $pdo->prepare('
                        INSERT INTO documents (title, file_path, document_type, uploaded_by) 
                        VALUES (?, ?, ?, ?)
                    ');
                    
                    if ($stmt->execute([$title, $file_path, $document_type, $currentUser['id']])) {
                        $success = 'Document uploaded successfully!';
                    } else {
                        $error = 'Failed to upload document.';
                    }
                } catch (PDOException $e) {
                    error_log('Document upload error: ' . $e->getMessage());
                    $error = 'Database error. Please try again.';
                }
            }
        }
    }
}

// Get documents data (HTTP GET)
try {
    // Get documents based on user role
    if (hasRole('admin')) {
        // Admins can see all documents
        $stmt = $pdo->query('
            SELECT d.*, u.username as uploaded_by_name 
            FROM documents d 
            LEFT JOIN users u ON d.uploaded_by = u.id 
            ORDER BY d.created_at DESC
        ');
    } else {
        // Regular users can only see public documents
        $stmt = $pdo->query('
            SELECT d.*, u.username as uploaded_by_name 
            FROM documents d 
            LEFT JOIN users u ON d.uploaded_by = u.id 
            ORDER BY d.created_at DESC
        ');
    }
    
    $documents = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log('Documents page error: ' . $e->getMessage());
    $documents = [];
    $error = 'Unable to load documents.';
}

function getDocumentTypeIcon($type) {
    switch ($type) {
        case 'insurance': return '🛡️';
        case 'financial': return '💰';
        case 'minutes': return '📝';
        default: return '📄';
    }
}

function getDocumentTypeBadge($type) {
    switch ($type) {
        case 'insurance': return 'bg-primary';
        case 'financial': return 'bg-success';
        case 'minutes': return 'bg-warning';
        default: return 'bg-secondary';
    }
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documents - Strata Management System</title>
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
        <h1>📄 Document Library</h1>
        <p class="text-muted mb-4">Access important strata documents and reports.</p>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <!-- Upload Document Form (Admin/Committee only) -->
        <?php if (hasAnyRole(['admin', 'committee'])): ?>
        <div class="card mb-4">
            <div class="card-header">
                <h5>Upload New Document</h5>
            </div>
            <div class="card-body">
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <input type="hidden" name="action" value="upload_document">
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="title" class="form-label">Document Title *</label>
                                <input type="text" class="form-control" id="title" name="title" 
                                       placeholder="e.g., Financial Report Q1 2024" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="document_type" class="form-label">Document Type *</label>
                                <select class="form-select" id="document_type" name="document_type" required>
                                    <option value="">Select type</option>
                                    <option value="insurance">Insurance</option>
                                    <option value="financial">Financial</option>
                                    <option value="minutes">Meeting Minutes</option>
                                    <option value="other">Other</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="file" class="form-label">Document File</label>
                        <input type="file" class="form-control" id="file" name="file" accept=".pdf,.doc,.docx">
                        <small class="text-muted">For demo purposes, the file upload is simulated. In production, this would handle actual file uploads.</small>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Upload Document</button>
                </form>
            </div>
        </div>
        <?php endif; ?>

        <!-- Documents Grid -->
        <?php if (empty($documents)): ?>
            <div class="alert alert-info">
                <h6>No documents found</h6>
                <p class="mb-0">
                    <?php if (hasAnyRole(['admin', 'committee'])): ?>
                        Upload the first document using the form above.
                    <?php else: ?>
                        No documents have been uploaded yet. Check back later.
                    <?php endif; ?>
                </p>
            </div>
        <?php else: ?>
            <div class="row">
                <?php foreach ($documents as $doc): ?>
                    <div class="col-lg-6 col-xl-4 mb-4">
                        <div class="card h-100">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <h5 class="card-title">
                                        <?php echo getDocumentTypeIcon($doc['document_type']); ?>
                                        <?php echo htmlspecialchars($doc['title']); ?>
                                    </h5>
                                    <span class="badge <?php echo getDocumentTypeBadge($doc['document_type']); ?>">
                                        <?php echo ucfirst(htmlspecialchars($doc['document_type'])); ?>
                                    </span>
                                </div>
                                
                                <div class="text-muted small mb-3">
                                    <div><strong>Uploaded:</strong> <?php echo date('M d, Y', strtotime($doc['created_at'])); ?></div>
                                    <div><strong>By:</strong> <?php echo htmlspecialchars($doc['uploaded_by_name'] ?? 'System'); ?></div>
                                    <?php if (hasRole('admin')): ?>
                                        <div><strong>File:</strong> <code class="small"><?php echo htmlspecialchars($doc['file_path']); ?></code></div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="card-footer bg-transparent">
                                <button class="btn btn-primary btn-sm me-2" 
                                        onclick="alert('Document preview: <?php echo htmlspecialchars($doc['title']); ?>\n\nIn a real system, this would open the PDF viewer.')">
                                    <i class="bi bi-eye"></i> View
                                </button>
                                <button class="btn btn-outline-secondary btn-sm" 
                                        onclick="alert('Download: <?php echo htmlspecialchars($doc['title']); ?>\n\nIn a real system, this would download the file.')">
                                    <i class="bi bi-download"></i> Download
                                </button>
                                <?php if (hasRole('admin') || $doc['uploaded_by'] == $currentUser['id']): ?>
                                    <button class="btn btn-outline-danger btn-sm ms-1" 
                                            onclick="if(confirm('Delete this document?')) alert('Document deletion feature would be implemented here.')">
                                        <i class="bi bi-trash"></i>
                                    </button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Document Statistics -->
            <div class="row mt-4">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6>Document Statistics</h6>
                        </div>
                        <div class="card-body">
                            <?php
                            $typeCounts = [];
                            foreach ($documents as $doc) {
                                $type = $doc['document_type'];
                                $typeCounts[$type] = ($typeCounts[$type] ?? 0) + 1;
                            }
                            ?>
                            <div class="row text-center">
                                <div class="col-6">
                                    <h4><?php echo count($documents); ?></h4>
                                    <small class="text-muted">Total Documents</small>
                                </div>
                                <div class="col-6">
                                    <h4><?php echo count(array_unique(array_column($documents, 'uploaded_by'))); ?></h4>
                                    <small class="text-muted">Contributors</small>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <h6 class="small mb-2">By Type:</h6>
                            <?php foreach ($typeCounts as $type => $count): ?>
                                <div class="d-flex justify-content-between">
                                    <span><?php echo getDocumentTypeIcon($type); ?> <?php echo ucfirst($type); ?>:</span>
                                    <strong><?php echo $count; ?></strong>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6>Document Access Guidelines</h6>
                        </div>
                        <div class="card-body">
                            <ul class="list-unstyled small">
                                <li>🔒 <strong>Insurance documents:</strong> Available to all owners</li>
                                <li>💰 <strong>Financial reports:</strong> Quarterly and annual statements</li>
                                <li>📝 <strong>Meeting minutes:</strong> AGM and committee meetings</li>
                                <li>📄 <strong>Other documents:</strong> Bylaws, maintenance schedules</li>
                            </ul>
                            
                            <?php if (hasAnyRole(['admin', 'committee'])): ?>
                                <div class="alert alert-info small mt-3">
                                    <strong>Note:</strong> As a <?php echo $currentUser['role']; ?>, you can upload new documents using the form above.
                                </div>
                            <?php else: ?>
                                <div class="alert alert-light small mt-3">
                                    <strong>Note:</strong> Contact the committee to request additional documents.
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <div class="mt-4">
            <a href="/api/index.php" class="btn btn-secondary">Back to Dashboard</a>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 