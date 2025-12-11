<?php
include 'functions.php';
start_session();

// Security check: Only Admins can access
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}

global $conn;
$message = '';

// --- ACTION LOGIC START ---

// 0. CSV TEMPLATE DOWNLOAD LOGIC (NEW SECTION)
if (isset($_GET['action']) && $_GET['action'] == 'download_template') {
    // 1. Define the content of the CSV template
    $csv_content = "Name,Email,Role,Class,Card_Number\n";
    $csv_content .= "John Doe,john.doe@school.edu,student,9A,1234567890\n";
    $csv_content .= "Jane Smith,jane.smith@school.edu,staff,,987654321\n";
    $csv_content .= "Bob Johnson,bob.johnson@example.com,parent,,\n";

    $filename = "bulk_upload_template.csv";

    // 2. Set the necessary HTTP headers to force a download
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');

    // 3. Output the CSV content and exit
    echo $csv_content;
    exit;
}

// 0. CSV EXPORT LOGIC START (Existing logic)
if (isset($_GET['action']) && $_GET['action'] == 'export_users') {
    // 1. Set headers for CSV download
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="user_export_' . date('Ymd_His') . '.csv"');
    header('Pragma: no-cache');
    header('Expires: 0');

    // 2. Open output stream
    $output = fopen('php://output', 'w');

    // 3. Define the CSV column headers
    $headers = [
        'ID',
        'Name',
        'Email',
        'Role',
        'Card_Number',
        'Class',
        'Password_Hash (Internal)'
    ];
    fputcsv($output, $headers);

    // 4. Fetch all user data
    $sql = "SELECT id, name, email, role, card_number, class, password_hash FROM users ORDER BY role, name";
    $result = $conn->query($sql);

    // 5. Output data rows
    if ($result && $result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            // Re-order and flatten the array to match headers
            $rowData = [
                $row['id'],
                $row['name'],
                $row['email'],
                $row['role'],
                $row['card_number'],
                $row['class'],
                $row['password_hash']
            ];
            fputcsv($output, $rowData);
        }
    }

    // 6. Close the output stream and exit to prevent further HTML output
    fclose($output);
    exit;
}
// --- CSV EXPORT LOGIC END ---


// 1. Add Single User
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_user'])) {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $role = $_POST['role'];
    $class = $role === 'student' ? trim($_POST['class']) : NULL;
    $card_number = in_array($role, ['student', 'staff']) ? trim($_POST['card_number']) : NULL;

    $temp_password = substr(md5(uniqid(rand(), true)), 0, 8);
    $password_hash = password_hash($temp_password, PASSWORD_DEFAULT);

    try {
        $stmt = $conn->prepare("INSERT INTO users (name, email, role, class, card_number, password_hash) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssss", $name, $email, $role, $class, $card_number, $password_hash);

        if ($stmt->execute()) {
            $message = "<div class='alert alert-success'>User **" . htmlspecialchars($name) . "** (" . htmlspecialchars($role) . ") added successfully. Initial password: **$temp_password**.</div>";
        } else {
            $message = "<div class='alert alert-danger'>Error adding user: " . htmlspecialchars($conn->error) . "</div>";
        }
        $stmt->close();
    } catch (Exception $e) {
        $message = "<div class='alert alert-danger'>Error: Email or Card Number might already exist.</div>";
    }
}

// 2. Delete User
if (isset($_GET['action']) && $_GET['action'] == 'delete' && isset($_GET['user_id'])) {
    $user_id = (int)$_GET['user_id'];

    // Checks if the user is the currently logged-in admin
    if ($user_id == $_SESSION['user_id']) {
        $message = "<div class='alert alert-danger'>Cannot delete the currently logged-in user.</div>";
    } else {
        $conn->begin_transaction();
        try {
            // Delete related entries first
            $conn->query("DELETE FROM meal_logs WHERE student_id = $user_id OR staff_id = $user_id");
            $conn->query("DELETE FROM parent_student WHERE parent_id = $user_id OR student_id = $user_id");

            $stmt = $conn->prepare("DELETE FROM users WHERE id = ? AND role != 'admin'");
            $stmt->bind_param("i", $user_id);
            if ($stmt->execute() && $stmt->affected_rows > 0) {
                $conn->commit();
                $message = "<div class='alert alert-warning'>User deleted successfully.</div>";
            } else {
                $conn->rollback();
                $message = "<div class='alert alert-danger'>Error deleting user, user is an admin, or user does not exist.</div>";
            }
            $stmt->close();
        } catch (Exception $e) {
            $conn->rollback();
            $message = "<div class='alert alert-danger'>Database error during deletion: " . $e->getMessage() . "</div>";
        }
    }
}

// 3. User Pairing (Parent to Student)
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['pair_user'])) {
    $parent_id = (int)$_POST['parent_id'];
    $student_id = (int)$_POST['student_id'];

    $check_sql = "SELECT * FROM parent_student WHERE parent_id = $parent_id AND student_id = $student_id";
    if ($conn->query($check_sql)->num_rows == 0) {
        $stmt = $conn->prepare("INSERT INTO parent_student (parent_id, student_id) VALUES (?, ?)");
        $stmt->bind_param("ii", $parent_id, $student_id);
        if ($stmt->execute()) {
            $message = "<div class='alert alert-success'>Parent-Student paired successfully.</div>";
        } else {
            $message = "<div class='alert alert-danger'>Error pairing users: " . htmlspecialchars($conn->error) . "</div>";
        }
        $stmt->close();
    } else {
        $message = "<div class='alert alert-info'>This pairing already exists.</div>";
    }
}

// 4. Add Meal
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_meal'])) {
    $meal_name = trim($_POST['meal_name']);
    $meal_description = trim($_POST['meal_description']);
    $meal_type = $_POST['meal_type'] ?? 'Lunch';

    try {
        $stmt = $conn->prepare("INSERT INTO meals (name, description, type) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $meal_name, $meal_description, $meal_type);

        if ($stmt->execute()) {
            $message = "<div class='alert alert-success'>Meal **" . htmlspecialchars($meal_name) . "** (" . htmlspecialchars($meal_type) . ") added successfully.</div>";
        } else {
            $message = "<div class='alert alert-danger'>Error adding meal: " . htmlspecialchars($conn->error) . "</div>";
        }
        $stmt->close();
    } catch (Exception $e) {
        $message = "<div class='alert alert-danger'>Error: Meal name might already exist.</div>";
    }
}

// 5. Delete Meal
if (isset($_GET['action']) && $_GET['action'] == 'delete_meal' && isset($_GET['meal_id'])) {
    $meal_id = (int)$_GET['meal_id'];

    $stmt = $conn->prepare("DELETE FROM meals WHERE id = ?");
    $stmt->bind_param("i", $meal_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        $message = "<div class='alert alert-warning'>Meal deleted successfully.</div>";
    } else {
        $message = "<div class='alert alert-danger'>Error deleting meal, or meal does not exist.</div>";
    }
    $stmt->close();
}

// 6. Reset User Password
if (isset($_GET['action']) && $_GET['action'] == 'reset_password' && isset($_GET['user_id'])) {
    $user_id = (int)$_GET['user_id'];

    // Prevent admin from resetting their own password this way (or primary admin)
    $user_role_result = $conn->query("SELECT role FROM users WHERE id = $user_id");
    if ($user_role_result && ($user_id == $_SESSION['user_id'] || $user_role_result->fetch_assoc()['role'] == 'admin')) {
        $message = "<div class='alert alert-danger'>Cannot reset password for an Admin account via this interface.</div>";
    } else {
        // Generate a secure temporary password
        $new_password = substr(md5(uniqid(rand(), true)), 0, 8);
        $password_hash = password_hash($new_password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $stmt->bind_param("si", $password_hash, $user_id);

        if ($stmt->execute() && $stmt->affected_rows > 0) {
            $user_info = $conn->query("SELECT name, email FROM users WHERE id = $user_id")->fetch_assoc();
            $message = "<div class='alert alert-warning'>Password for **" . htmlspecialchars($user_info['name']) . "** (" . htmlspecialchars($user_info['email']) . ") has been reset. New Temporary Password: **$new_password**.</div>";
        } else {
            $message = "<div class='alert alert-danger'>Error resetting password, user not found.</div>";
        }
        $stmt->close();
    }
}

// 7. Bulk User Upload (Core processing logic)
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['bulk_upload_csv']) && isset($_FILES['csv_file'])) {
    $file = $_FILES['csv_file'];
    $success_count = 0;
    $error_details = [];
    $users_to_add = [];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $message = "<div class='alert alert-danger'>Bulk Upload Error: File upload failed. Code: " . $file['error'] . "</div>";
    } else {
        $conn->begin_transaction();
        $upload_success = true;

        // Open the uploaded CSV file
        if (($handle = fopen($file['tmp_name'], "r")) !== FALSE) {
            // Read header row (to ignore it)
            fgetcsv($handle, 1000, ",");

            while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
                // Expected CSV columns: name, email, role, class, card_number
                if (count($data) < 3) {
                    $error_details[] = "Skipped row due to insufficient data.";
                    continue;
                }

                $name = trim($data[0] ?? '');
                $email = trim($data[1] ?? '');
                $role = strtolower(trim($data[2] ?? ''));
                $class = isset($data[3]) ? trim($data[3]) : NULL;
                $card_number = isset($data[4]) ? trim(str_replace('"', '', $data[4])) : NULL; // Clean card number

                if (empty($name) || empty($email) || empty($role)) continue;

                if (!in_array($role, ['admin', 'staff', 'student', 'parent'])) {
                    $error_details[] = "Invalid role specified for: " . htmlspecialchars($email);
                    continue;
                }

                // Prepare data for insertion
                $class = $role === 'student' ? $class : NULL;
                $card_number = in_array($role, ['student', 'staff']) ? $card_number : NULL;
                $temp_password = substr(md5(uniqid(rand(), true)), 0, 8);
                $password_hash = password_hash($temp_password, PASSWORD_DEFAULT);

                try {
                    $stmt = $conn->prepare("INSERT INTO users (name, email, role, class, card_number, password_hash) VALUES (?, ?, ?, ?, ?, ?)");
                    $stmt->bind_param("ssssss", $name, $email, $role, $class, $card_number, $password_hash);

                    if ($stmt->execute()) {
                        $success_count++;
                        $users_to_add[] = [
                            'email' => $email,
                            'password' => $temp_password,
                            'role' => $role
                        ];
                    } else {
                        // Check for duplicate key error (1062)
                        if ($conn->errno == 1062) {
                            $error_details[] = "Duplicate entry (Email or Card Number) for: " . htmlspecialchars($email);
                        } else {
                            $error_details[] = "DB Error for " . htmlspecialchars($email) . ": " . $conn->error;
                        }
                        $upload_success = false;
                    }
                    $stmt->close();
                } catch (Exception $e) {
                    $error_details[] = "Exception for " . htmlspecialchars($email) . ": " . $e->getMessage();
                    $upload_success = false;
                }
            }
            fclose($handle);
        } else {
            $message = "<div class='alert alert-danger'>Bulk Upload Error: Could not open uploaded file.</div>";
            $upload_success = false;
        }

        if ($success_count > 0) {
            $conn->commit();
            $password_button = "<button class='btn btn-sm btn-light ms-3' onclick='document.getElementById(\"bulk-results\").style.display=\"block\"'>Show Passwords</button>";
            $message = "<div class='alert alert-success'>Successfully added $success_count users in bulk. $password_button</div>";
            if (!empty($error_details)) {
                   $message .= "<div class='alert alert-warning mt-2'>Warnings/Errors during upload: " . count(array_unique($error_details)) . " rows skipped/failed. Check console for details.</div>";
            }
            $_SESSION['bulk_results'] = $users_to_add;
        } else if (!$upload_success) {
            $conn->rollback();
            $message = "<div class='alert alert-danger'>Bulk Upload Failed: 0 users added. Errors: " . implode('; ', array_unique($error_details)) . "</div>";
        } else {
             $conn->rollback(); // No users added, but no fatal errors
             $message = "<div class='alert alert-info'>Bulk Upload completed but no new users were added (file might be empty or all rows failed).</div>";
        }
    }
}

// 8. Unlink Parent/Student
if (isset($_GET['action']) && $_GET['action'] == 'unlink' && isset($_GET['parent_id']) && isset($_GET['student_id'])) {
    $parent_id = (int)$_GET['parent_id'];
    $student_id = (int)$_GET['student_id'];

    $stmt = $conn->prepare("DELETE FROM parent_student WHERE parent_id = ? AND student_id = ?");
    $stmt->bind_param("ii", $parent_id, $student_id);

    if ($stmt->execute() && $stmt->affected_rows > 0) {
        // Redirect back to the links section to see the update
        header('Location: admin_dashboard.php#link-management');
        exit;
    } else {
        $message = "<div class='alert alert-danger'>Error unlinking users, or pairing did not exist.</div>";
    }
    $stmt->close();
}
// --- ACTION LOGIC END ---


// --- DATA RETRIEVAL START ---

// 1. User Counts for Cards
$user_counts = [];
$roles = ['admin', 'staff', 'student', 'parent'];
foreach ($roles as $role) {
    $result = $conn->query("SELECT COUNT(*) as count FROM users WHERE role = '$role'");
    $user_counts[$role] = $result->fetch_assoc()['count'];
}
$result = $conn->query("SELECT COUNT(*) as count FROM users");
$user_counts['total'] = $result->fetch_assoc()['count'];

// 2. Fetch Users for Table
$sql_users_fetch = "SELECT id, name, email, role, card_number, class FROM users ORDER BY role, name";
$users = $conn->query($sql_users_fetch)->fetch_all(MYSQLI_ASSOC);

// 3. Fetch Parents and Students for Pairing Modal
$parents = $conn->query("SELECT id, name, email FROM users WHERE role = 'parent' ORDER BY name")->fetch_all(MYSQLI_ASSOC);
$students = $conn->query("SELECT id, name, class, email FROM users WHERE role = 'student' ORDER BY class, name")->fetch_all(MYSQLI_ASSOC);

// 4. Fetch Meals for Table
$meals_result = $conn->query("SELECT id, name, description, type FROM meals ORDER BY type, name");
$meals = $meals_result ? $meals_result->fetch_all(MYSQLI_ASSOC) : [];

// 5. Meal Count for Card
$meal_count_result = $conn->query("SELECT COUNT(*) as count FROM meals");
$meal_count = $meal_count_result ? $meal_count_result->fetch_assoc()['count'] : 0;

// 6. Fetch Parent/Student Links for Table
$sql_links = "SELECT
    ps.parent_id, up.name AS parent_name, up.email AS parent_email,
    ps.student_id, us.name AS student_name, us.class AS student_class
FROM parent_student ps
JOIN users up ON ps.parent_id = up.id
JOIN users us ON ps.student_id = us.id
ORDER BY parent_name, student_name";
$links_result = $conn->query($sql_links);
$links = $links_result ? $links_result->fetch_all(MYSQLI_ASSOC) : [];

// --- DATA RETRIEVAL END ---


// --- REPORT GENERATION LOGIC ---

$today = date('Y-m-d');

// A. Daily Meal Summary Metrics
$summary_q = $conn->prepare("
    SELECT
        COUNT(id) AS total_served,
        MIN(log_time) AS first_scan,
        MAX(log_time) AS last_scan
    FROM meal_logs
    WHERE DATE(log_time) = ?
");
$summary_q->bind_param("s", $today);
$summary_q->execute();
$daily_summary = $summary_q->get_result()->fetch_assoc();
$summary_q->close();

$total_served_today = $daily_summary['total_served'] ?? 0;
$first_scan_time = $daily_summary['first_scan'] ? date('h:i A', strtotime($daily_summary['first_scan'])) : 'N/A';
$last_scan_time = $daily_summary['last_scan'] ? date('h:i A', strtotime($daily_summary['last_scan'])) : 'N/A';

// Calculate coverage percentage using the existing student count
$total_students = $user_counts['student'];
$percentage_served = ($total_students > 0) ? round(($total_served_today / $total_students) * 100, 1) : 0;


// B. Latest Meal Logs for Table
$logs_q = $conn->prepare("
    SELECT
        ml.log_time,
        u_student.name AS student_name,
        u_student.class,
        u_staff.name AS staff_name
    FROM meal_logs ml
    JOIN users u_student ON ml.student_id = u_student.id
    LEFT JOIN users u_staff ON ml.staff_id = u_staff.id
    ORDER BY ml.log_time DESC
    LIMIT 50
");
$logs_q->execute();
$logs_result = $logs_q->get_result();

// --- REPORT GENERATION LOGIC END ---

// Display bulk upload results if available
if (isset($_SESSION['bulk_results']) && is_array($_SESSION['bulk_results'])) {
    $results_html = "<div id='bulk-results' class='alert alert-info mt-3' style='display:none;'>
        <h5>Bulk Upload Passwords:</h5>
        <ul>";
    foreach ($_SESSION['bulk_results'] as $user) {
        $results_html .= "<li>**" . htmlspecialchars($user['email']) . "** (" . ucfirst($user['role']) . ") - Temp Password: **" . htmlspecialchars($user['password']) . "**</li>";
    }
    $results_html .= "</ul><p class='text-muted small'>Please securely store these credentials as they will disappear upon navigation.</p></div>";
    $message .= $results_html;
    unset($_SESSION['bulk_results']); // Clear after displaying
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Meal System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        body { background-color: #f4f7f9; }
        .sidebar {
            background-color: #1f2937;
            color: white;
            min-height: 100vh;
            position: sticky;
            top: 0;
            height: 100vh;
        }
        .nav-link { color: #d1d5db; }
        .nav-link:hover { color: white; background-color: #374151; }
        .nav-link.active { background-color: #374151; color: white; }
        .card { border-radius: 0.75rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1); }
        .stat-card { transition: transform 0.3s, box-shadow 0.3s; cursor: pointer; }
        .stat-card:hover { transform: translateY(-3px); box-shadow: 0 8px 15px rgba(0, 0, 0, 0.2); }
        .table-responsive { max-height: 500px; overflow-y: auto; }
        .meal-badge { font-weight: bold; padding: 0.35em 0.65em; border-radius: 0.5rem; }
        /* Custom class for balancing 5 cards in a row */
        .col-md-fifth {
            flex: 0 0 auto;
            width: 20%;
        }
        @media (max-width: 768px) {
            .col-md-fifth {
                width: 50%; /* 2 cards per row on mobile */
            }
        }
        /* New styling for report cards */
        .report-card { border-left: 5px solid; }
    </style>
</head>
<body>

<div class="d-flex">
    <div class="sidebar p-3 d-flex flex-column" style="width: 250px;">
        <h4 class="text-white mb-4 border-bottom pb-2">Admin Panel</h4>
        <nav class="nav nav-pills flex-column">
            <a class="nav-link active rounded-lg mb-2" href="#"><i class="fas fa-chart-line me-2"></i> Dashboard</a>
            <a class="nav-link rounded-lg mb-2" href="#user-management"><i class="fas fa-users me-2"></i> User Management</a>
            <a class="nav-link rounded-lg mb-2" href="#link-management"><i class="fas fa-link me-2"></i> Link Management</a>
            <a class="nav-link rounded-lg mb-2" href="#meal-management"><i class="fas fa-utensils me-2"></i> Meal Management</a>
            <a class="nav-link rounded-lg mb-2" href="#logs"><i class="fas fa-history me-2"></i> Meal History</a>
            <a class="nav-link rounded-lg mb-2 mt-auto" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i> Logout</a>
        </nav>
    </div>

    <div class="flex-grow-1 p-4">
        <h1 class="mb-4">Welcome, <?php echo htmlspecialchars($_SESSION['name']); ?></h1>

        <?php echo $message; // Display message (success/error) ?>

        <div class="row mb-5 g-3 justify-content-center">

            <div class="col-md-fifth col-sm-6">
                <div class="card stat-card bg-primary text-white p-3">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-users fa-3x me-3"></i>
                        <div>
                            <h5 class="mb-0">Total Users</h5>
                            <p class="h3"><?php echo $user_counts['total']; ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-fifth col-sm-6">
                <div class="card stat-card bg-success text-white p-3">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-graduation-cap fa-3x me-3"></i>
                        <div>
                            <h5 class="mb-0">Students</h5>
                            <p class="h3"><?php echo $user_counts['student']; ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-fifth col-sm-6">
                <div class="card stat-card bg-info text-white p-3">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-user-tie fa-3x me-3"></i>
                        <div>
                            <h5 class="mb-0">Staff</h5>
                            <p class="h3"><?php echo $user_counts['staff']; ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-fifth col-sm-6">
                <div class="card stat-card bg-warning text-dark p-3">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-users-cog fa-3x me-3"></i>
                        <div>
                            <h5 class="mb-0">Parents</h5>
                            <p class="h3"><?php echo $user_counts['parent']; ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-fifth col-sm-6">
                <div class="card stat-card bg-danger text-white p-3">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-utensils fa-3x me-3"></i>
                        <div>
                            <h5 class="mb-0">Defined Meals</h5>
                            <p class="h3"><?php echo $meal_count; ?></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>


        <h2 class="mb-3 text-primary"><i class="fas fa-chart-bar me-2"></i> Daily Meal Reports</h2>

        <div class="row mb-5 g-3">

            <div class="col-md-4">
                <div class="card shadow report-card border-primary">
                    <div class="card-body">
                        <h5 class="card-title text-primary"><i class="fas fa-drumstick-bite me-1"></i> Meals Served Today</h5>
                        <h1 class="display-4"><?php echo $total_served_today; ?></h1>
                        <p class="card-text text-muted">Out of <?php echo $total_students; ?> registered students</p>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card shadow report-card border-success">
                    <div class="card-body">
                        <h5 class="card-title text-success"><i class="fas fa-percent me-1"></i> Coverage Rate</h5>
                        <h1 class="display-4"><?php echo $percentage_served; ?>%</h1>
                        <p class="card-text text-muted">Total unique students served today.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card shadow report-card border-warning">
                    <div class="card-body">
                        <h5 class="card-title text-warning"><i class="fas fa-clock me-1"></i> Operation Times</h5>
                        <p class="mb-1">First Scan: <strong><?php echo $first_scan_time; ?></strong></p>
                        <p class="mb-0">Last Scan: <strong><?php echo $last_scan_time; ?></strong></p>
                    </div>
                </div>
            </div>
        </div>


        <div id="user-management" class="card p-4 mb-5">
            <h4 class="card-title mb-4 border-bottom pb-2">User Management</h4>

            <div class="d-flex justify-content-between mb-3 flex-wrap gap-2">
                <div class="d-flex flex-wrap gap-2">
                    <button class="btn btn-success rounded-lg" data-bs-toggle="modal" data-bs-target="#addUserModal"><i class="fas fa-user-plus me-2"></i> Add Single User</button>
                    <button class="btn btn-primary rounded-lg" data-bs-toggle="modal" data-bs-target="#bulkUploadModal"><i class="fas fa-upload me-2"></i> Bulk User Upload (CSV)</button>
                </div>

                <a href="admin_dashboard.php?action=export_users" class="btn btn-info rounded-lg text-white"><i class="fas fa-download me-2"></i> Download All Users CSV</a>
            </div>

            <div class="d-flex mb-3 align-items-center">
                <div class="me-3 flex-shrink-0">
                    <label for="role-filter" class="form-label visually-hidden">Filter by Role</label>
                    <select id="role-filter" name="role" class="form-select rounded-lg">
                        <option value="all">All Roles</option>
                        <option value="admin">Admin</option>
                        <option value="staff">Staff</option>
                        <option value="student">Student</option>
                        <option value="parent">Parent</option>
                    </select>
                </div>
                <div class="input-group">
                    <input type="text" id="user-search" class="form-control rounded-start-lg" placeholder="Live Search by Name, Email, or Card Number">
                    <button class="btn btn-secondary rounded-end-lg" type="button" disabled><i class="fas fa-search"></i> Live</button>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-hover" id="users-table">
                    <thead class="bg-light sticky-top">
                        <tr>
                            <th>#</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Card No.</th>
                            <th>Class</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr data-name="<?php echo htmlspecialchars(strtolower($user['name'])); ?>"
                                data-email="<?php echo htmlspecialchars(strtolower($user['email'])); ?>"
                                data-card="<?php echo htmlspecialchars(strtolower($user['card_number'] ?? '')); ?>"
                                data-role="<?php echo htmlspecialchars(strtolower($user['role'])); ?>">

                                <td><?php echo $user['id']; ?></td>
                                <td><?php echo htmlspecialchars($user['name']); ?></td>
                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                <td><span class="badge bg-<?php echo get_role_color($user['role']); ?>"><?php echo ucfirst($user['role']); ?></span></td>
                                <td><?php echo htmlspecialchars($user['card_number'] ?? '-'); ?></td>
                                <td><?php echo htmlspecialchars($user['class'] ?? '-'); ?></td>
                                <td>
                                    <?php
                                        $is_current_user = $user['id'] == $_SESSION['user_id'];
                                        $is_admin = $user['role'] === 'admin';

                                        // Reset Password Action
                                        if (!$is_admin && !$is_current_user):
                                    ?>
                                        <a href="admin_dashboard.php?action=reset_password&user_id=<?php echo $user['id']; ?>" class="btn btn-sm btn-outline-warning rounded-lg me-1" onclick="return confirm('Are you sure you want to reset the password for <?php echo htmlspecialchars($user['name']); ?>? A new temporary password will be generated.');" title="Reset Password"><i class="fas fa-key"></i></a>
                                    <?php else: ?>
                                        <button class="btn btn-sm btn-outline-secondary rounded-lg me-1 disabled" title="Cannot reset admin/own password"><i class="fas fa-key"></i></button>
                                    <?php endif; ?>

                                    <?php if (!$is_current_user && !$is_admin): ?>
                                        <a href="admin_dashboard.php?action=delete&user_id=<?php echo $user['id']; ?>" class="btn btn-sm btn-outline-danger rounded-lg" onclick="return confirm('Are you sure you want to delete this user? This action is irreversible.');" title="Delete User"><i class="fas fa-trash-alt"></i></a>
                                    <?php else: ?>
                                        <button class="btn btn-sm btn-outline-secondary rounded-lg disabled" title="Cannot delete primary admin or yourself"><i class="fas fa-trash-alt"></i></button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($users)): ?>
                            <tr><td colspan="7" class="text-center">No users found matching the criteria.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <div id="link-management" class="card p-4 mb-5">
            <h4 class="card-title mb-4 border-bottom pb-2">Parent/Student Link Management</h4>

            <div class="d-flex justify-content-end mb-3">
                <button class="btn btn-info rounded-lg text-white" data-bs-toggle="modal" data-bs-target="#pairUserModal"><i class="fas fa-link me-2"></i> Create New Pairing</button>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead class="bg-light sticky-top">
                        <tr>
                            <th>Parent Name (Email)</th>
                            <th>Student Name (Class)</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($links as $link): ?>
                            <tr>
                                <td>
                                    <strong><?php echo htmlspecialchars($link['parent_name']); ?></strong>
                                    <br><span class="text-muted small"><?php echo htmlspecialchars($link['parent_email']); ?></span>
                                </td>
                                <td>
                                    <strong><?php echo htmlspecialchars($link['student_name']); ?></strong>
                                    (Class: <?php echo htmlspecialchars($link['student_class'] ?? 'N/A'); ?>)
                                </td>
                                <td>
                                    <a href="admin_dashboard.php?action=unlink&parent_id=<?php echo $link['parent_id']; ?>&student_id=<?php echo $link['student_id']; ?>"
                                        class="btn btn-sm btn-outline-danger rounded-lg"
                                        onclick="return confirm('Are you sure you want to unlink <?php echo htmlspecialchars($link['parent_name']); ?> from <?php echo htmlspecialchars($link['student_name']); ?>?');"
                                        title="Unlink Pairing"><i class="fas fa-unlink"></i> Unlink</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($links)): ?>
                            <tr><td colspan="3" class="text-center">No parent-student links found.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <div id="meal-management" class="card p-4 mb-5">
            <h4 class="card-title mb-4 border-bottom pb-2">Meal Management (Menu Items)</h4>

            <div class="d-flex justify-content-end mb-3">
                <button class="btn btn-danger rounded-lg" data-bs-toggle="modal" data-bs-target="#addMealModal"><i class="fas fa-plus-circle me-2"></i> Add New Meal Item</button>
            </div>

            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead class="bg-light sticky-top">
                        <tr>
                            <th>#</th>
                            <th>Meal Name</th>
                            <th>Description</th>
                            <th>Type</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($meals as $meal): ?>
                            <tr>
                                <td><?php echo $meal['id']; ?></td>
                                <td><?php echo htmlspecialchars($meal['name']); ?></td>
                                <td><?php echo htmlspecialchars($meal['description']); ?></td>
                                <td>
                                    <?php
                                        // PHP 7.x Compatible Switch for Meal Type Color
                                        $type_class = '';
                                        switch ($meal['type']) {
                                            case 'Breakfast': $type_class = 'bg-info text-white'; break;
                                            case 'Lunch': $type_class = 'bg-success text-white'; break;
                                            case 'Dinner': $type_class = 'bg-warning text-dark'; break;
                                            default: $type_class = 'bg-secondary text-white'; break;
                                        }
                                    ?>
                                    <span class="meal-badge <?php echo $type_class; ?>"><?php echo htmlspecialchars($meal['type']); ?></span>
                                </td>
                                <td>
                                    <a href="admin_dashboard.php?action=delete_meal&meal_id=<?php echo $meal['id']; ?>" class="btn btn-sm btn-outline-danger rounded-lg" onclick="return confirm('Are you sure you want to delete the meal: <?php echo htmlspecialchars($meal['name']); ?>? This cannot be undone.');" title="Delete Meal"><i class="fas fa-trash-alt"></i></a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($meals)): ?>
                            <tr><td colspan="5" class="text-center">No meal items have been defined yet.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <div id="logs" class="card p-4 mb-5">
            <h4 class="card-title mb-4 border-bottom pb-2"><i class="fas fa-history me-2"></i> Meal History (Latest 50 Logs)</h4>

            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead class="bg-light sticky-top">
                        <tr>
                            <th>Log Time</th>
                            <th>Student Name</th>
                            <th>Class</th>
                            <th>Served By (Staff)</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($log = $logs_result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo date('Y-m-d h:i:s A', strtotime($log['log_time'])); ?></td>
                            <td><?php echo htmlspecialchars($log['student_name']); ?></td>
                            <td><?php echo htmlspecialchars($log['class']); ?></td>
                            <td><?php echo htmlspecialchars($log['staff_name'] ?? 'N/A'); ?></td>
                        </tr>
                        <?php endwhile; ?>
                        <?php if ($logs_result->num_rows === 0): ?>
                        <tr><td colspan="4" class="text-center text-muted">No meal logs found.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <?php $logs_q->close(); // Close the prepared statement ?>
        </div>
        </div>
</div>
<div class="modal fade" id="addUserModal" tabindex="-1" aria-labelledby="addUserModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-success text-white">
                <h5 class="modal-title" id="addUserModalLabel"><i class="fas fa-user-plus me-2"></i> Add New User</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="admin_dashboard.php">
                <div class="modal-body">
                    <input type="hidden" name="add_user" value="1">

                    <div class="mb-3">
                        <label for="role" class="form-label">Role</label>
                        <select class="form-select" id="role" name="role" required onchange="toggleUserFields()">
                            <option value="student">Student</option>
                            <option value="parent">Parent</option>
                            <option value="staff">Staff</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="name" class="form-label">Full Name</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email (Unique Login)</label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>

                    <div id="class-group" class="mb-3">
                        <label for="class" class="form-label">Class/Grade</label>
                        <input type="text" class="form-control" id="class" name="class">
                    </div>
                    <div id="card-group" class="mb-3">
                        <label for="card_number" class="form-label">Card/QR Number (Unique)</label>
                        <input type="text" class="form-control" id="card_number" name="card_number">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-success">Add User</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="bulkUploadModal" tabindex="-1" aria-labelledby="bulkUploadModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-primary text-white">
                <h5 class="modal-title" id="bulkUploadModalLabel"><i class="fas fa-upload me-2"></i> Bulk User Upload (CSV)</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="admin_dashboard.php" enctype="multipart/form-data">
                <div class="modal-body">
                    <input type="hidden" name="bulk_upload_csv" value="1">

                    <div class="alert alert-info py-2 mb-3 d-flex align-items-center">
                        <i class="fas fa-download me-2"></i>
                        Download the required format:
                        <a href="admin_dashboard.php?action=download_template" class="btn btn-sm btn-info ms-2">Template CSV</a>
                    </div>
                    <p>Upload a CSV file containing user data. The file should have the following columns in order (the header row will be skipped):</p>
                    <ul>
                        <li>Name (Required)</li>
                        <li>Email (Required, Unique)</li>
                        <li>Role (Required: `admin`, `staff`, `student`, or `parent`)</li>
                        <li>Class (Optional, only for `student`)</li>
                        <li>Card\_Number (Optional, only for `student` or `staff`, Unique)</li>
                    </ul>

                    <div class="mb-3">
                        <label for="csv_file" class="form-label">Select CSV File</label>
                        <input class="form-control" type="file" id="csv_file" name="csv_file" accept=".csv" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary"><i class="fas fa-cloud-upload-alt me-1"></i> Upload Users</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="pairUserModal" tabindex="-1" aria-labelledby="pairUserModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-info text-white">
                <h5 class="modal-title" id="pairUserModalLabel"><i class="fas fa-link me-2"></i> Pair Parent and Student</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="admin_dashboard.php">
                <div class="modal-body">
                    <input type="hidden" name="pair_user" value="1">

                    <div class="mb-3">
                        <label for="parent_id" class="form-label">Select Parent</label>
                        <select class="form-select" id="parent_id" name="parent_id" required>
                            <option value="">--- Select Parent ---</option>
                            <?php foreach ($parents as $p): ?>
                                <option value="<?php echo $p['id']; ?>"><?php echo htmlspecialchars($p['name']); ?> (<?php echo htmlspecialchars($p['email']); ?>)</option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="mb-3">
                        <label for="student_id" class="form-label">Select Student</label>
                        <select class="form-select" id="student_id" name="student_id" required>
                            <option value="">--- Select Student ---</option>
                            <?php foreach ($students as $s): ?>
                                <option value="<?php echo $s['id']; ?>"><?php echo htmlspecialchars($s['name']); ?> (Class: <?php echo htmlspecialchars($s['class']); ?>)</option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-info text-white">Pair Users</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="addMealModal" tabindex="-1" aria-labelledby="addMealModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-danger text-white">
                <h5 class="modal-title" id="addMealModalLabel"><i class="fas fa-plus-circle me-2"></i> Add New Meal Item</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="POST" action="admin_dashboard.php">
                <div class="modal-body">
                    <input type="hidden" name="add_meal" value="1">

                    <div class="mb-3">
                        <label for="meal_name" class="form-label">Meal Name</label>
                        <input type="text" class="form-control" id="meal_name" name="meal_name" required>
                    </div>
                    <div class="mb-3">
                        <label for="meal_description" class="form-label">Description</label>
                        <textarea class="form-control" id="meal_description" name="meal_description" rows="2"></textarea>
                    </div>
                    <div class="mb-3">
                        <label for="meal_type" class="form-label">Meal Type</label>
                        <select class="form-select" id="meal_type" name="meal_type" required>
                            <option value="Lunch">Lunch</option>
                            <option value="Breakfast">Breakfast</option>
                            <option value="Dinner">Dinner</option>
                            <option value="Snack">Snack</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Save Meal Item</button>
                </div>
            </form>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
    // Function to toggle conditional fields in the Add User Modal
    function toggleUserFields() {
        const role = document.getElementById('role').value;
        const classGroup = document.getElementById('class-group');
        const cardGroup = document.getElementById('card-group');

        // Reset required state
        document.getElementById('class').removeAttribute('required');
        document.getElementById('card_number').removeAttribute('required');

        // Toggle visibility and set required status
        if (role === 'student') {
            classGroup.style.display = 'block';
            cardGroup.style.display = 'block';
            document.getElementById('class').setAttribute('required', 'required');
            document.getElementById('card_number').setAttribute('required', 'required');
        } else if (role === 'staff') {
            classGroup.style.display = 'none';
            cardGroup.style.display = 'block';
            document.getElementById('card_number').setAttribute('required', 'required');
        } else { // parent, admin
            classGroup.style.display = 'none';
            cardGroup.style.display = 'none';
        }
    }

    // Call on page load to set initial state
    document.addEventListener('DOMContentLoaded', toggleUserFields);


    // Client-Side Filtering and Search Functionality
    document.addEventListener('DOMContentLoaded', function() {
        const searchInput = document.getElementById('user-search');
        const roleFilter = document.getElementById('role-filter');
        const tableBody = document.querySelector('#users-table tbody');
        const rows = tableBody.querySelectorAll('tr');

        // Function to apply both filters
        const applyFilter = () => {
            const searchTerm = searchInput.value.toLowerCase().trim();
            const selectedRole = roleFilter.value;
            let foundRows = 0;

            rows.forEach(row => {
                const rowRole = row.getAttribute('data-role');
                const rowName = row.getAttribute('data-name');
                const rowEmail = row.getAttribute('data-email');
                const rowCard = row.getAttribute('data-card');

                // 1. Role Filter Check
                const roleMatch = (selectedRole === 'all' || rowRole === selectedRole);

                // 2. Search Term Check (search name, email, or card number)
                const searchMatch = (
                    rowName.includes(searchTerm) ||
                    rowEmail.includes(searchTerm) ||
                    rowCard.includes(searchTerm)
                );

                if (roleMatch && searchMatch) {
                    row.style.display = '';
                    foundRows++;
                } else {
                    row.style.display = 'none';
                }
            });

            // Handle No Results row (Simple check, assumes only data rows are in the tbody initially)
            let noResultsRow = tableBody.querySelector('.no-results-row');

            if (foundRows === 0) {
                if (!noResultsRow) {
                     const newRow = tableBody.insertRow();
                     newRow.classList.add('no-results-row');
                     const cell = newRow.insertCell();
                     cell.colSpan = 7;
                     cell.classList.add('text-center', 'text-muted');
                     cell.textContent = 'No users found matching the filter and search criteria.';
                     tableBody.appendChild(newRow); // Append the new row
                } else {
                     noResultsRow.style.display = '';
                }
            } else if (noResultsRow) {
                noResultsRow.style.display = 'none';
            }
        };

        // Attach event listeners
        searchInput.addEventListener('keyup', applyFilter);
        roleFilter.addEventListener('change', applyFilter);

        // Initial application of the filter
        applyFilter();
    });

    // Optional: Scroll to the correct anchor if a redirect occurred
    document.addEventListener('DOMContentLoaded', function() {
        if (window.location.hash) {
            document.querySelector(window.location.hash).scrollIntoView({ behavior: 'smooth' });
        }
    });

</script>
</body>
</html>

