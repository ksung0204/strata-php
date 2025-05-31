<?php
header('Content-Type: text/plain');

// Check environment variables
$vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS', 'DB_PORT'];
$env_ok = true;
foreach ($vars as $var) {
    if (getenv($var) === false || getenv($var) === '') {
        echo "Missing or empty env variable: $var\n";
        $env_ok = false;
    } else {
        echo "$var: " . getenv($var) . "\n";
    }
}

// Check database connection
if ($env_ok) {
    require_once __DIR__ . '/../database/config.php';
    if (isset($pdo) && $pdo instanceof PDO) {
        echo "Database connection: OK\n";
    } else {
        echo "Database connection: FAILED\n";
    }
} else {
    echo "Skipped DB check due to missing env variables.\n";
}

echo "Health check complete."; 