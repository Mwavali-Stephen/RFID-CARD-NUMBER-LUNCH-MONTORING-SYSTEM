<?php
// Include your core functions file
require_once 'functions.php'; 

// Ensure session is started for consistency, although not strictly needed for this page alone
start_session(); 

$message = '';
$is_valid_token = false;
$user_email = '';
$token = '';

// Check if email and token are present in the URL (GET request for initial access)
if (isset($_GET['email']) && isset($_GET['token'])) {
    $user_email = filter_input(INPUT_GET, 'email', FILTER_SANITIZE_EMAIL);
    $token = filter_input(INPUT_GET, 'token', FILTER_SANITIZE_STRING);

    // Initial validation check
    $is_valid_token = validate_reset_token($user_email, $token);

    if (!$is_valid_token) {
        $message = '<p class="text-red-600 font-bold">The password reset link is invalid or has expired. Please request a new one.</p>';
    }
} else {
    // If accessed without parameters
    $message = '<p class="text-red-600 font-bold">Access Denied. You must follow the link sent to your email.</p>';
}

// --- Handle Form Submission (POST request for setting new password) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_password'])) {
    // Sanitize and collect data from POST
    $user_email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    // Basic server-side validation
    if ($new_password !== $confirm_password) {
        $message = '<p class="text-red-600">Error: Passwords do not match.</p>';
        $is_valid_token = true; // Keep form visible for retry
    } elseif (strlen($new_password) < 8) {
        $message = '<p class="text-red-600">Error: Password must be at least 8 characters long.</p>';
        $is_valid_token = true; // Keep form visible for retry
    } else {
        // Re-validate token before update (critical security step)
        if (validate_reset_token($user_email, $token)) {
            
            if (update_user_password($user_email, $token, $new_password)) {
                $message = '<p class="text-green-600 font-bold text-xl">Success! Your password has been updated. You can now log in.</p>';
                $is_valid_token = false; // Hide form after successful reset
                // Clear session messages related to password reset request if any
                unset($_SESSION['reset_email_sent']);
            } else {
                $message = '<p class="text-red-600">A database error occurred during password update. Please try again.</p>';
                $is_valid_token = true; // Keep form visible
            }
        } else {
            $message = '<p class="text-red-600 font-bold">Security Error: The token is no longer valid. Please request a new link.</p>';
            $is_valid_token = false;
        }
    }
}
// If it was a POST submission, and the token was initially valid, we need to re-validate $is_valid_token
// if it wasn't set by the submission handler.
// This handles the case where the user lands on the page via GET and submits the form via POST.
elseif (isset($_POST['email']) && isset($_POST['token'])) {
    $user_email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
    // If POST failed validation but we want to show the form again, we must re-validate the token for display
    if (!isset($is_valid_token) || !$is_valid_token) {
        $is_valid_token = validate_reset_token($user_email, $token);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <!-- Tailwind CSS for basic styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom styles to ensure nice look */
        .min-h-screen { min-height: 100vh; }
    </style>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-8 rounded-xl shadow-2xl w-full max-w-md border-t-4 border-indigo-600">
        <h1 class="text-3xl font-extrabold text-gray-800 mb-6 text-center">Set New Password</h1>
        
        <div id="status-message" class="mb-6 p-4 rounded-md text-center bg-gray-50 border border-gray-200">
            <?php echo $message; ?>
        </div>

        <?php if ($is_valid_token): ?>
        <form action="reset_password.php" method="POST" class="space-y-4">
            <!-- Hidden inputs to pass email and token back to the POST request -->
            <input type="hidden" name="email" value="<?php echo htmlspecialchars($user_email); ?>">
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

            <div>
                <label for="new_password" class="block text-sm font-semibold text-gray-700">New Password (Min. 8 characters)</label>
                <input type="password" id="new_password" name="new_password" required minlength="8"
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 transition duration-150 ease-in-out">
            </div>

            <div>
                <label for="confirm_password" class="block text-sm font-semibold text-gray-700">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required minlength="8"
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 transition duration-150 ease-in-out">
            </div>

            <button type="submit"
                    class="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-md text-base font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition duration-150 ease-in-out">
                Reset Password
            </button>
        </form>
        <?php endif; ?>
        
        <div class="mt-8 text-center border-t pt-4">
            <a href="index.php" class="text-indigo-600 hover:text-indigo-500 font-medium text-sm transition duration-150">
                &larr; Go back to login
            </a>
        </div>
    </div>
</body>
</html>