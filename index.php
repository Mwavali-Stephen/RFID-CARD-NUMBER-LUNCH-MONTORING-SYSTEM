<?php
include 'functions.php';
start_session(); // Start session and initialize CSRF token

global $conn;
$message = '';
$message_type = '';

// Check if the user is already logged in and redirect them immediately
if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
    redirect_by_role($_SESSION['role']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CRITICAL: Validate CSRF token immediately on POST
    validate_csrf_token(); 
    
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        $message = "Please enter both email and password.";
        $message_type = 'danger';
    } else {
        
        // 1. Prepare and execute the query to fetch user data and the password hash
        $sql = "SELECT id, name, password_hash, role, class, card_number FROM users WHERE email = ?";
        $stmt = $conn->prepare($sql);
        
        if (!$stmt) {
             // Handle preparation error
             $message = "Database error: Could not prepare statement. Please check the SQL query.";
             $message_type = 'danger';
        } else {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $stmt->close();

            // 2. Password Verification
            if ($user && password_verify($password, $user['password_hash'])) {
                // Success! Regenerate session ID to prevent Session Fixation
                regenerate_session_id();
                
                // Set session variables.
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['name'] = $user['name'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['class'] = $user['class'];
                $_SESSION['card_number'] = $user['card_number'];

                // Use the shared redirection function
                redirect_by_role($user['role']);
                
            } else {
                
                // --- Temporary Debug Logging (Remove after successful login) ---
                if ($user) {
                    error_log("LOGIN FAILED for email: {$email}. DB Hash: {$user['password_hash']}. Input Password: {$password}");
                } else {
                    error_log("LOGIN FAILED: User not found for email: {$email}");
                }
                // -----------------------------------------------------------------
                
                $message = "Invalid email or password.";
                $message_type = 'danger';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Canteen Login - Meal System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        /* Deep Blue Background */
        body { background-color: #007bff; /* Standard Bootstrap Primary Blue */
               display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        
        /* Login Container Styling */
        .login-container { 
            max-width: 400px; 
            padding: 2.5rem; 
            border-radius: 1rem; 
            box-shadow: 0 0 30px rgba(0, 0, 0, 0.2); 
            background-color: white; 
        }
        
        /* Ensuring text is visible against the dark background */
        .card-header {
            background-color: #0056b3; /* Slightly darker blue for header */
            color: white;
            border-radius: 1rem 1rem 0 0 !important;
        }
    </style>
</head>
<body>
<div class="login-container">
    <h2 class="text-center mb-4 text-primary">
        <i class="fas fa-utensils me-2"></i> Meal Access Portal
    </h2>

    <?php if ($message): ?>
        <div class="alert alert-<?php echo $message_type; ?>"><?php echo $message; ?></div>
    <?php endif; ?>

    <form method="POST">
        <?php echo csrf_token_tag(); ?>
        
        <div class="mb-3">
            <label for="email" class="form-label">Email Address</label>
            <input type="email" class="form-control" id="email" name="email" required autofocus>
        </div>
        <div class="mb-4">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>
        
        <button type="submit" class="btn btn-primary w-100">Log In</button>
    </form>
    
    <p class="text-center mt-3 small text-muted">
        Forgot Password? Consult your system administrator.
    </p>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
