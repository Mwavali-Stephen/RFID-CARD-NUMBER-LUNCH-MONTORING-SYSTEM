<?php
// Include the core functions, which contains the start_session() function
include 'functions.php';

// Start the session if it hasn't been already
start_session();

// 1. Unset all session variables
$_SESSION = array();

// 2. Destroy the session
session_destroy();

// 3. Redirect the user back to the login page
header("Location: index.php");
exit;
?>