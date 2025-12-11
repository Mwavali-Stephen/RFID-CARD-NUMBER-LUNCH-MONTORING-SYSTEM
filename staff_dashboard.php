<?php
include 'functions.php'; // Includes database connection ($conn) and start_session()
start_session();

// Security check: Only Staff or Admin can access
if (!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['staff', 'admin'])) {
    header('Location: index.php');
    exit;
}

// Ensure the database connection is available
global $conn; 
$message = '';
$scanned_student = null;

// --- Meal Logging Logic (Simulating Scan) ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['scan_card'])) {
    
    // Simple validation (can be enhanced with CSRF if forms are added)
    $card_number = trim($_POST['card_number']);
    if (empty($card_number)) {
        $message = "<div class='alert alert-danger'>Card number cannot be empty.</div>";
    } else {
        $staff_id = $_SESSION['user_id'];
        $current_meal_name = 'Standard Lunch'; // Define the meal being served
    
        // 1. Find the student by card number
        $stmt = $conn->prepare("SELECT id, name, class, card_number FROM users WHERE card_number = ? AND role = 'student'");
        $stmt->bind_param("s", $card_number);
        $stmt->execute();
        $result = $stmt->get_result();
        $scanned_student = $result->fetch_assoc();
        $stmt->close();
    
        if ($scanned_student) {
            $student_id = $scanned_student['id'];
            
            // 2. Check if the student already had lunch today (Simple limit: 1 log per day)
            $today = date('Y-m-d');
            $check_log_stmt = $conn->prepare("SELECT id FROM meal_logs WHERE student_id = ? AND DATE(log_time) = ?");
            $check_log_stmt->bind_param("is", $student_id, $today);
            $check_log_stmt->execute();
            $check_log_result = $check_log_stmt->get_result();
            $check_log_stmt->close();
    
            if ($check_log_result->num_rows > 0) {
                $message = "<div class='alert alert-warning'>{$scanned_student['name']} has already been served lunch today.</div>";
            } else {
                // 3. Log the meal
                $log_stmt = $conn->prepare("INSERT INTO meal_logs (student_id, staff_id, meal_name) VALUES (?, ?, ?)");
                $log_stmt->bind_param("iis", $student_id, $staff_id, $current_meal_name);
                
                if ($log_stmt->execute()) {
                    $message = "<div class='alert alert-success'>Meal successfully logged for <strong>{$scanned_student['name']}</strong> ({$scanned_student['class']}).</div>";
                    
                    // --- REMOVED EMAIL NOTIFICATION LOGIC ---
                    // The logic to look up parents and call send_email() was removed here 
                    // to resolve the "Call to undefined function send_email()" fatal error.
                    // If you wish to implement this later, you must define the send_email() function in functions.php.
                    // ----------------------------------------

                } else {
                    $message = "<div class='alert alert-danger'>Error logging meal: " . $conn->error . "</div>";
                }
                $log_stmt->close();
            }
    
        } else {
            $message = "<div class='alert alert-danger'>Student Card/QR Code not found or user is not a student.</div>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Staff Dashboard - Meal Scan</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        body { background-color: #e5e7eb; }
        .scan-card { max-width: 600px; margin: 50px auto; padding: 40px; border-radius: 1rem; box-shadow: 0 10px 25px rgba(0,0,0,0.1); background-color: white; }
        .scan-input { font-size: 1.5rem; text-align: center; height: 70px; }
        .btn-scan { background-color: #22c55e; border-color: #22c55e; transition: background-color 0.3s; height: 70px; font-size: 1.25rem; }
        .btn-scan:hover { background-color: #16a34a; border-color: #16a34a; }
        .student-info-box { border: 1px solid #d1d5db; padding: 20px; border-radius: 0.75rem; background-color: #f9fafb; }
    </style>
</head>
<body>

    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">Staff Portal</a>
            <span class="navbar-text me-auto text-white">
                Welcome, <?php echo htmlspecialchars($_SESSION['name']); ?> (<?php echo ucfirst($_SESSION['role']); ?>)
            </span>
            <a href="logout.php" class="btn btn-outline-light rounded-lg"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>
    </nav>

    <div class="container">
        <div class="scan-card">
            <h2 class="text-center text-primary mb-4"><i class="fas fa-qrcode me-2"></i> Meal Scan Point</h2>
            <p class="text-center text-muted">Scan the student's card/QR Code or manually enter the Card Number below for Lunch service.</p>
            
            <?php echo $message; // Display message (success/warning/error) ?>

            <form method="POST" action="staff_dashboard.php" class="mb-4">
                <input type="hidden" name="scan_card" value="1">
                <div class="input-group">
                    <input type="text" name="card_number" class="form-control scan-input rounded-start-lg" placeholder="Enter Card/QR Number" autofocus required>
                    <button class="btn btn-scan text-white rounded-end-lg" type="submit"><i class="fas fa-utensils me-2"></i> Log Meal</button>
                </div>
            </form>

            <?php if ($scanned_student): ?>
                <div class="student-info-box mt-4">
                    <h4 class="text-success mb-3"><i class="fas fa-check-circle me-2"></i> Student Verified</h4>
                    <div class="row">
                        <div class="col-6"><p class="mb-1"><strong>Name:</strong> <?php echo htmlspecialchars($scanned_student['name']); ?></p></div>
                        <div class="col-6"><p class="mb-1"><strong>Class:</strong> <?php echo htmlspecialchars($scanned_student['class']); ?></p></div>
                        <div class="col-6"><p class="mb-0"><strong>Card Number:</strong> <?php echo htmlspecialchars($scanned_student['card_number']); ?></p></div>
                        <div class="col-6"><p class="mb-0"><strong>Meal:</strong> Standard Lunch</p></div>
                    </div>
                </div>
            <?php else: ?>
                <div class="student-info-box mt-4 text-center text-muted">
                    <i class="fas fa-id-card fa-3x mb-3"></i>
                    <p>Ready to scan. Student details will appear here upon successful scan.</p>
                </div>
            <?php endif; ?>

        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>