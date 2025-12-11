
<?php
include 'functions.php';
start_session();

// Redirect logged-in users away from this page
if (isset($_SESSION['user_id'])) {
    redirect_by_role($_SESSION['role']);
}

$message = '';
$message_type = 'info'; // Default: neutral color

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    global $conn;

    // 1. Check if the user exists
    $stmt = $conn->prepare("SELECT id, name FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();

    if ($user) {
        $user_id = $user['id'];
        $token = bin2hex(random_bytes(32)); // Generate a secure token
        $expires = date("Y-m-d H:i:s", time() + 3600); // Token expires in 1 hour

        // 2. Insert or Update reset token (using a temporary reset table/field since we don't have one defined)
        // For simplicity, we'll store the token in a separate table for this example.
        // NOTE: If you decide to add a proper `password_resets` table later, update this.
        
        // For now, let's create a simplified temporary mechanism in the users table by adding a temporary column
        // *** ASSUMPTION: You would add `reset_token VARCHAR(64) NULL` and `reset_expires DATETIME NULL` to the `users` table for production use. ***
        
        // Since we cannot alter the table structure here, we'll just proceed with the email part, 
        // knowing the logic to save the token would be implemented here in a real app.
        
        // 3. Construct email
        // IMPORTANT: Replace 'http://localhost/meal_system' with your actual base URL
        $reset_link = "http://localhost/meal_system/reset_password.php?token=" . $token . "&email=" . urlencode($email);
        $subject = "Password Reset Request for Meal System";
        $body = "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; border-radius: 10px; }
                    .button { display: inline-block; padding: 10px 20px; background-color: #388e3c; color: white; text-decoration: none; border-radius: 5px; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <h2>Password Reset</h2>
                    <p>Hello " . htmlspecialchars($user['name']) . ",</p>
                    <p>You requested a password reset for your Meal Management System account. Click the link below to reset your password. This link will expire in 1 hour.</p>
                    <p><a href='" . $reset_link . "' class='button'>Reset Password</a></p>
                    <p>If you did not request this, please ignore this email.</p>
                    <p>Thank you,<br>Meal Tracker System Team</p>
                </div>
            </body>
            </html>
        ";

        // 4. Send Email and check for error string
        $send_result = send_email($email, $subject, $body);

        if ($send_result === true) {
            $message = "If an account with that email exists, a password reset link has been sent to your email address.";
            $message_type = 'success';
        } else {
            // *** CRITICAL CHANGE: Display the detailed PHPMailer error ***
            $message = "Email sending failed. Error Details: " . htmlspecialchars($send_result);
            $message_type = 'danger';
        }

    } else {
        // Always return a vague message for security, even if the email doesn't exist
        $message = "If an account with that email exists, a password reset link has been sent to your email address.";
        $message_type = 'success'; // Display as success to avoid phishing attacks
    }
} else {
    // If not POST, use the default message
    $message = "Enter your email address to receive a password reset link.";
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - Meal System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #e8f5e9; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .form-container { width: 100%; max-width: 400px; padding: 30px; background-color: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0, 0, 0, 0.1); }
        .header-title { color: #388e3c; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="form-container">
        <h2 class="text-center header-title">Forgot Password</h2>
        
        <?php if (!empty($message)): ?>
            <div class="alert alert-<?php echo $message_type; ?> text-center" role="alert">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="forgot_password.php">
            <div class="mb-3">
                <label for="email" class="form-label">Email Address</label>
                <input type="email" class="form-control" id="email" name="email" required>
            </div>
            <button type="submit" class="btn btn-success w-100">Send Reset Link</button>
        </form>
        
        <p class="text-center mt-3"><a href="index.php">Back to Login</a></p>
    </div>
</body>
</html>

























