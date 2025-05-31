<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Building Information - Strata Management System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .hero-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 60px 0;
        }
        .info-card {
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s;
        }
        .info-card:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/api/index.php">Strata Management</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/public_info.php">Building Info</a>
                <a class="nav-link" href="/api/pages/login.php">Owner Login</a>
                <a class="nav-link" href="/api/pages/register.php">Register</a>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-8">
                    <h1 class="display-4 fw-bold">Skyline Apartments</h1>
                    <p class="lead mb-4">Modern strata-titled residential complex in the heart of Sydney</p>
                    <div class="row">
                        <div class="col-md-4">
                            <div class="d-flex align-items-center mb-3">
                                <i class="bi bi-building fs-3 me-3"></i>
                                <div>
                                    <h5 class="mb-0">15 Floors</h5>
                                    <small>Premium High-Rise</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center mb-3">
                                <i class="bi bi-house fs-3 me-3"></i>
                                <div>
                                    <h5 class="mb-0">120 Units</h5>
                                    <small>1, 2 & 3 Bedroom</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center mb-3">
                                <i class="bi bi-calendar3 fs-3 me-3"></i>
                                <div>
                                    <h5 class="mb-0">Est. 2020</h5>
                                    <small>Modern Construction</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-4 text-center">
                    <img src="https://via.placeholder.com/400x300/667eea/ffffff?text=Skyline+Apartments" 
                         alt="Building" class="img-fluid rounded shadow">
                </div>
            </div>
        </div>
    </section>

    <div class="container my-5">
        <!-- Building Information Cards -->
        <div class="row mb-5">
            <div class="col-lg-4 mb-4">
                <div class="card info-card h-100">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <i class="bi bi-geo-alt-fill text-primary fs-3 me-3"></i>
                            <h5 class="card-title mb-0">Location</h5>
                        </div>
                        <p class="card-text">
                            <strong>Address:</strong><br>
                            123 Harbour Street<br>
                            Sydney NSW 2000<br><br>
                            <strong>Transport:</strong><br>
                            • 2 min walk to Circular Quay Station<br>
                            • Direct bus routes to CBD<br>
                            • Nearby ferry terminal
                        </p>
                    </div>
                </div>
            </div>

            <div class="col-lg-4 mb-4">
                <div class="card info-card h-100">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <i class="bi bi-star-fill text-warning fs-3 me-3"></i>
                            <h5 class="card-title mb-0">Amenities</h5>
                        </div>
                        <ul class="list-unstyled">
                            <li>🏊‍♂️ Rooftop swimming pool</li>
                            <li>🏋️‍♂️ Fully equipped gym</li>
                            <li>🎯 BBQ & entertainment area</li>
                            <li>🚗 Secure underground parking</li>
                            <li>📦 Concierge & mail services</li>
                            <li>🌿 Landscaped gardens</li>
                            <li>👥 Conference room</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="col-lg-4 mb-4">
                <div class="card info-card h-100">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <i class="bi bi-shield-check text-success fs-3 me-3"></i>
                            <h5 class="card-title mb-0">Security & Services</h5>
                        </div>
                        <ul class="list-unstyled">
                            <li>🔒 24/7 security monitoring</li>
                            <li>📹 CCTV surveillance</li>
                            <li>🔑 Swipe card access</li>
                            <li>🚨 Fire safety systems</li>
                            <li>🛠️ On-site maintenance</li>
                            <li>📞 Emergency response</li>
                            <li>♻️ Waste management</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- Strata Management Information -->
        <div class="row mb-5">
            <div class="col-12">
                <h2 class="text-center mb-4">Strata Management Information</h2>
            </div>
            <div class="col-lg-6 mb-4">
                <div class="card info-card">
                    <div class="card-body">
                        <h5 class="card-title">
                            <i class="bi bi-people-fill text-primary me-2"></i>
                            Owners Corporation
                        </h5>
                        <p><strong>Total Units:</strong> 120</p>
                        <p><strong>Unit Entitlements:</strong></p>
                        <ul>
                            <li>1 Bedroom: 1 entitlement (40 units)</li>
                            <li>2 Bedroom: 2 entitlements (60 units)</li>
                            <li>3 Bedroom: 3 entitlements (20 units)</li>
                        </ul>
                        <p><strong>Total Entitlements:</strong> 200</p>
                        <p class="text-muted small">Unit entitlements determine voting rights and levy contributions</p>
                    </div>
                </div>
            </div>

            <div class="col-lg-6 mb-4">
                <div class="card info-card">
                    <div class="card-body">
                        <h5 class="card-title">
                            <i class="bi bi-calendar-event text-warning me-2"></i>
                            Important Meetings
                        </h5>
                        <div class="mb-3">
                            <strong>Annual General Meeting (AGM)</strong><br>
                            <small class="text-muted">Usually held in March each year</small>
                        </div>
                        <div class="mb-3">
                            <strong>Extraordinary General Meetings</strong><br>
                            <small class="text-muted">Called as needed for urgent matters</small>
                        </div>
                        <div class="mb-3">
                            <strong>Committee Meetings</strong><br>
                            <small class="text-muted">Monthly on first Tuesday</small>
                        </div>
                        <div class="alert alert-info small">
                            All owners are notified of meetings via post and email 14 days in advance
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Contact Information -->
        <div class="row mb-5">
            <div class="col-12">
                <div class="card info-card">
                    <div class="card-body">
                        <h5 class="card-title text-center mb-4">
                            <i class="bi bi-telephone-fill text-primary me-2"></i>
                            Contact Information
                        </h5>
                        <div class="row">
                            <div class="col-md-4 text-center mb-3">
                                <h6>Strata Manager</h6>
                                <p>
                                    Sydney Strata Services<br>
                                    📞 (02) 1234 5678<br>
                                    📧 skyline@strataservices.com.au<br>
                                    🕐 Mon-Fri 9AM-5PM
                                </p>
                            </div>
                            <div class="col-md-4 text-center mb-3">
                                <h6>Emergency Maintenance</h6>
                                <p>
                                    24/7 Emergency Line<br>
                                    📞 (02) 9999 0000<br>
                                    🚨 Fire/Police: 000<br>
                                    🔧 After hours repairs
                                </p>
                            </div>
                            <div class="col-md-4 text-center mb-3">
                                <h6>Building Manager</h6>
                                <p>
                                    On-site Office<br>
                                    📞 (02) 1234 5679<br>
                                    📧 manager@skylineapts.com.au<br>
                                    🕐 Mon-Fri 8AM-4PM
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Governance -->
        <div class="row">
            <div class="col-12">
                <div class="card info-card">
                    <div class="card-body">
                        <h5 class="card-title">
                            <i class="bi bi-file-text text-info me-2"></i>
                            Governance & Compliance
                        </h5>
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Legislation</h6>
                                <ul>
                                    <li>Strata Schemes Management Act 2015 (NSW)</li>
                                    <li>Strata Schemes Development Act 2015 (NSW)</li>
                                    <li>Work Health and Safety Act 2011 (NSW)</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6>Key Documents</h6>
                                <ul>
                                    <li>Strata Plan SP-123456</li>
                                    <li>By-laws and House Rules</li>
                                    <li>Insurance Certificates</li>
                                    <li>Building Maintenance Schedule</li>
                                </ul>
                            </div>
                        </div>
                        <div class="alert alert-success mt-3">
                            <strong>Registered Owners:</strong> 
                            <a href="/api/pages/login.php" class="alert-link">Login here</a> to access the owners portal for documents, levy payments, and maintenance requests.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="bg-dark text-light py-4">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <p>&copy; 2024 Skyline Apartments Owners Corporation. All rights reserved.</p>
                </div>
                <div class="col-md-6 text-end">
                    <p>Managed under NSW Strata Schemes Management Act 2015</p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 