<?php
// CRITICAL: Ensure functions.php is included first for DB connection and functions
include 'functions.php';

// Define the default admin credentials
$default_email = 'admin@example.com';
$default_password = 'password123';
$default_name = 'System Administrator';

// Hash the password securely - Generate a fresh hash every time this script runs
$password_hash = password_hash($default_password, PASSWORD_DEFAULT);

echo "<!DOCTYPE html><html><head><title>Admin Setup</title><link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'></head><body><div class='container mt-5'>";
echo "<h2>System Setup: Creating/Resetting Initial Admin User</h2>";

global $conn;

// 1. Check if the admin user already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND role = 'admin'");
$stmt->bind_param("s", $default_email);
$stmt->execute();
$result = $stmt->get_result();
$admin_exists = $result->num_rows > 0;
$stmt->close();

if ($admin_exists) {
    // Admin user exists, but authentication is failing. We will reset the password hash.
    
    echo "<div class='alert alert-info'>";
    echo "<strong>Admin User Found:</strong> An admin user with email '{$default_email}' exists. Since you are facing login issues, we will reset the password hash to ensure correctness.";
    echo "</div>";

    // Update the password hash for the existing admin
    $sql_update = "UPDATE users SET password_hash = ? WHERE email = ? AND role = 'admin'";
    $stmt_update = $conn->prepare($sql_update);
    
    if (!$stmt_update) {
        echo "<div class='alert alert-danger'>Database Error (Update): " . $conn->error . "</div>";
    } else {
        $stmt_update->bind_param("ss", $password_hash, $default_email);
        
        if ($stmt_update->execute()) {
            echo "<div class='alert alert-success'>";
            echo "<strong>PASSWORD RESET SUCCESS!</strong> The admin password hash has been successfully updated.<br>";
            echo "<strong>Email:</strong> <code>{$default_email}</code><br>";
            echo "<strong>Password:</strong> <code>{$default_password}</code><br>";
            echo "</div>";
            echo "<p>Please use these credentials to log in now. You can change the password on the dashboard later.</p>";
        } else {
            echo "<div class='alert alert-danger'>Failed to update admin password: " . $stmt_update->error . "</div>";
        }
        $stmt_update->close();
    }
} else {
    // Admin user does not exist, insert it
    echo "<div class='alert alert-info'>Admin user not found. Inserting new admin record.</div>";

    $sql_insert = "INSERT INTO users (name, email, role, password_hash) VALUES (?, ?, 'admin', ?)";
    $stmt_insert = $conn->prepare($sql_insert);
    
    if (!$stmt_insert) {
        echo "<div class='alert alert-danger'>Database Error (Insert): " . $conn->error . "</div>";
    } else {
        $stmt_insert->bind_param("sss", $default_name, $default_email, $password_hash);
        
        if ($stmt_insert->execute()) {
            echo "<div class='alert alert-success'>";
            echo "<strong>SUCCESS!</strong> Initial Admin user created.<br>";
            echo "<strong>Email:</strong> <code>{$default_email}</code><br>";
            echo "<strong>Password:</strong> <code>{$default_password}</code><br>";
            echo "</div>";
            echo "<p>Please log in with these credentials and **change the password immediately**.</p>";
        } else {
            echo "<div class='alert alert-danger'>Failed to create admin user: " . $stmt_insert->error . "</div>";
        }
        $stmt_insert->close();
    }
}

echo "<p><a href='login.php' class='btn btn-primary'>Go to Login Page</a></p>";
echo "</div></body></html>";
?>