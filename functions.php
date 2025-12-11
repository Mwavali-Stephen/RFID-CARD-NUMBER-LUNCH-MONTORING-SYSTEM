
<?php
// functions.php

// ------------------------------------
// Database Connection Configuration

define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'meal_tracker_db'); 

// Connect to MySQL database
$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Set character set for security
$conn->set_charset("utf8mb4");

/**
 * Starts a secure session, initializes the CSRF token
 
 */
function start_session() {
    if (session_status() === PHP_SESSION_NONE) {
        // Use secure session cookies
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_httponly', 1);
        // ini_set('session.cookie_secure', 1); // Enable in production with HTTPS
        
        session_start();
        
        // Initialize CSRF token if it doesn't exist
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        
        // Regenerate ID on initial start for extra fixation prevention
        if (!isset($_SESSION['initialized'])) {
            session_regenerate_id(true);
            $_SESSION['initialized'] = true;
        }
    }
}

//enerates the hidden input field for the CSRF token.
 
function csrf_token_tag() {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        start_session(); // Ensure session is active
    }
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($_SESSION['csrf_token']) . '">';
}

/**
 * Validates the CSRF token sent in a POST request.
 * Exits if validation fails.
 */
function validate_csrf_token() {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        start_session();
    }
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        // Mismatch or missing token: Likely CSRF attack
        error_log("CSRF Token validation failed for user_id: " . ($_SESSION['user_id'] ?? 'unknown'));
        die("Security error: Invalid request token. Please refresh and try again.");
    }
    // Token is valid; regenerate the token immediately for the next request (Token-per-Request Pattern)
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Regenerates the session ID to prevent Session Fixation.
 */
function regenerate_session_id() {
    session_regenerate_id(true);
}

// Redirecting user to their correct dashboard based on role
 
function redirect_by_role($role) {
    switch ($role) {
        case 'admin':
            header("Location: admin_dashboard.php");
            exit;

        case 'staff':
            header("Location: staff_dashboard.php");
            exit;

        case 'student':
            header("Location: student_dashboard.php");
            exit;
            
        case 'parent':
            header("Location: parent_dashboard.php");
            exit;

        default:
            // Fallback for unknown role
            header("Location: index.php");
            exit;
    }
}

/**
 * Helper function to get a Bootstrap color class based on user role.
 * USED BY admin_dashboard.php to color-code user roles in the table.
 * @param string $role The user's role string.
 * @return string The corresponding Bootstrap color class.
 */
function get_role_color(string $role): string {
    return match (strtolower($role)) {
        'admin' => 'danger',
        'staff' => 'info',
        'student' => 'success',
        'parent' => 'warning',
        default => 'secondary'
    };
}
?>


