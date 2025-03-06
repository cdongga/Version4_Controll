<?php
// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

$servername = "localhost"; // If using XAMPP or a local server
$username = "root"; // Default MySQL username
$password = ""; // Default password (leave empty for XAMPP)
$database = "department_store"; // Change this to your database name

// Create Connection
$conn = new mysqli($servername, $username, $password, $database);

// Check Connection
//if ($conn->connect_error) {
  //  die("Connection failed: " . $conn->connect_error);
//} else {
   // echo "Database connected successfully!";
//}
//?>
