<?php
include 'functions.php';
start_session();

// Security check: Only Parent can access
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'parent') {
    header('Location: index.php');
    exit;
}

global $conn;
$parent_id = $_SESSION['user_id'];
$message = '';

// --- 1. Fetch Linked Students ---
// Select all students linked to this parent
$students_q = $conn->prepare("
    SELECT 
        u.id AS student_id, 
        u.name AS student_name, 
        u.class,
        u.card_number
    FROM users u
    JOIN parent_student ps ON u.id = ps.student_id
    WHERE ps.parent_id = ? AND u.role = 'student'
    ORDER BY u.name ASC
");
$students_q->bind_param("i", $parent_id);
$students_q->execute();
$students_result = $students_q->get_result();
$linked_students = $students_result->fetch_all(MYSQLI_ASSOC);
$students_q->close();

// --- 2. Fetch Meal Logs for Today for all Linked Students ---
$today = date('Y-m-d');
$meal_statuses = [];

if (!empty($linked_students)) {
    // Create a comma-separated list of student IDs for the IN clause
    $student_ids = array_column($linked_students, 'student_id');
    $id_placeholders = implode(',', array_fill(0, count($student_ids), '?'));
    $id_types = str_repeat('i', count($student_ids));
    
    // Query to get today's meal log for all linked students
    // We use a separate query to fetch log details
    $log_q = $conn->prepare("
        SELECT 
            student_id, 
            meal_name, 
            log_time,
            (SELECT name FROM users WHERE id = staff_id) AS staff_name
        FROM meal_logs 
        WHERE student_id IN ($id_placeholders) AND DATE(log_time) = ?
    ");
    
    // Bind all student IDs first, then the date
    $bind_params = array_merge($student_ids, [$today]);
    $log_q->bind_param($id_types . 's', ...$bind_params);
    $log_q->execute();
    $log_result = $log_q->get_result();
    
    // Organize logs by student_id for easy lookup
    while ($log = $log_result->fetch_assoc()) {
        $meal_statuses[$log['student_id']] = $log;
    }
    $log_q->close();
}

// Function to determine meal status display
function get_meal_status_display($student_id, $meal_statuses) {
    if (isset($meal_statuses[$student_id])) {
        $log = $meal_statuses[$student_id];
        $time = date('h:i A', strtotime($log['log_time']));
        $staff = htmlspecialchars($log['staff_name']);
        $meal = htmlspecialchars($log['meal_name']);
        return "<span class='badge bg-success p-2'><i class='fas fa-check-circle me-1'></i> Served at $time</span>
                <p class='text-muted small mt-1 mb-0'>Meal: $meal, Served by: $staff</p>";
    } else {
        return "<span class='badge bg-warning p-2'><i class='fas fa-clock me-1'></i> Awaiting Meal Service</span>";
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parent Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        body { background-color: #f7f7f9; }
        .card-meal { border-left: 5px solid #0d6efd; }
        .status-box { padding: 10px 15px; border-radius: 0.5rem; }
    </style>
</head>
<body>

    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="#">Parent Portal</a>
            <span class="navbar-text me-auto text-white">
                Welcome, <?php echo $_SESSION['name']; ?> (<?php echo ucfirst($_SESSION['role']); ?>)
            </span>
            <a href="logout.php" class="btn btn-outline-light rounded-lg"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>
    </nav>

    <div class="container my-5">
        <h2 class="mb-4 text-center text-primary"><i class="fas fa-child me-2"></i> Children's Meal Status for <?php echo date('l, F jS'); ?></h2>

        <?php if (empty($linked_students)): ?>
            <div class="alert alert-info text-center">
                <i class="fas fa-info-circle me-2"></i> You currently have no students linked to your account.
            </div>
        <?php else: ?>
            <div class="row row-cols-1 row-cols-md-2 g-4">
                <?php foreach ($linked_students as $student): ?>
                    <div class="col">
                        <div class="card shadow-sm h-100 card-meal">
                            <div class="card-body">
                                <h4 class="card-title text-dark">
                                    <i class="fas fa-user-graduate me-2 text-primary"></i> <?php echo htmlspecialchars($student['student_name']); ?>
                                </h4>
                                <p class="card-text mb-2">
                                    <small class="text-muted">Class: <?php echo htmlspecialchars($student['class']); ?> | Card: <?php echo htmlspecialchars($student['card_number']); ?></small>
                                </p>
                                <hr>
                                <h5 class="mb-3">Today's Meal Status:</h5>
                                <div class="status-box bg-light">
                                    <?php echo get_meal_status_display($student['student_id'], $meal_statuses); ?>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>