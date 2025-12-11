<?php
include 'functions.php';
start_session();

// Security check: Only Students can access this page
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'student') {
    // If not logged in or not a student, redirect to the index/login page
    header('Location: index.php');
    exit;
}

global $conn;
$user_id = $_SESSION['user_id'];
$student_name = htmlspecialchars($_SESSION['name']);
$student_class = htmlspecialchars($_SESSION['class']);

// --- Data Retrieval for Student Dashboard ---

// 1. Fetch Student's Meal Logs
$sql_logs = "SELECT log_time, meal_name 
             FROM meal_logs 
             WHERE student_id = ?
             ORDER BY log_time DESC 
             LIMIT 15"; // Showing the last 15 logs

$stmt_logs = $conn->prepare($sql_logs);
$stmt_logs->bind_param("i", $user_id);
$stmt_logs->execute();
$meal_logs = $stmt_logs->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt_logs->close();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Dashboard - Meal System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        body { background-color: #e6f7ff; } /* Light blue background for a student theme */
        .header-bar { background-color: #007bff; color: white; }
        .card { 
            border-radius: 1rem; 
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); 
            transition: transform 0.3s;
        }
        .card:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.15);
        }
        .meal-log-card { min-height: 400px; }
        .table-responsive { max-height: 350px; overflow-y: auto; }
        .table thead th { position: sticky; top: 0; background: #f8f9fa; z-index: 10; }
    </style>
</head>
<body>

<div class="header-bar py-3 mb-4 shadow-sm">
    <div class="container d-flex justify-content-between align-items-center">
        <h4 class="mb-0">Student Meal Tracker</h4>
        <a href="logout.php" class="btn btn-light btn-sm rounded-pill"><i class="fas fa-sign-out-alt me-2"></i> Logout</a>
    </div>
</div>

<div class="container pb-5">
    <h1 class="mb-4 text-primary">Welcome Back, <?php echo $student_name; ?>!</h1>

    <div class="row g-4 mb-5">
        <!-- Student Info Card -->
        <div class="col-md-6">
            <div class="card bg-white p-4 h-100">
                <h5 class="card-title text-success"><i class="fas fa-user-circle me-2"></i> My Profile</h5>
                <hr>
                <p class="h4 mb-3"><strong>Name:</strong> <?php echo $student_name; ?></p>
                <p class="h4 mb-0"><strong>Class:</strong> <span class="badge bg-primary fs-5"><?php echo $student_class; ?></span></p>
                <p class="text-muted mt-3">This information is managed by the school administration.</p>
            </div>
        </div>

        <!-- Parent Info Card (Simulated Feature) -->
        <div class="col-md-6">
            <div class="card bg-light p-4 h-100 border-info">
                <h5 class="card-title text-info"><i class="fas fa-house-user me-2"></i> Parent/Guardian Access</h5>
                <hr>
                <p class="text-muted">
                    If your parent or guardian is linked to your account, they can also view this meal history using their separate Parent/Guardian login.
                </p>
                <p class="mb-0">
                    <i class="fas fa-bell me-2 text-warning"></i> Notifications about your meal attendance are sent to them.
                </p>
            </div>
        </div>
    </div>

    <!-- Meal Log History Section -->
    <div class="card meal-log-card p-4">
        <h3 class="card-title mb-4 border-bottom pb-2 text-secondary"><i class="fas fa-utensils me-2"></i> Recent Meal History</h3>
        
        <p class="text-muted">Showing your last 15 recorded meals.</p>

        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead>
                    <tr class="table-light">
                        <th>#</th>
                        <th>Meal Served</th>
                        <th>Date & Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($meal_logs)): ?>
                        <tr>
                            <td colspan="3" class="text-center text-muted">No meal logs recorded for you yet.</td>
                        </tr>
                    <?php else: ?>
                        <?php $counter = 1; foreach ($meal_logs as $log): ?>
                            <tr>
                                <td><?php echo $counter++; ?></td>
                                <td><span class="badge bg-success"><?php echo htmlspecialchars($log['meal_name']); ?></span></td>
                                <td><?php echo date('F j, Y, g:i a', strtotime($log['log_time'])); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        
        <div class="d-flex justify-content-center mt-3">
             <button class="btn btn-outline-secondary btn-sm" disabled>View Full History (Future Feature)</button>
        </div>
    </div>
    
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>