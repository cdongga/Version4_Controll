<?php
include 'db_connect.php'; // Connects to database
session_start();

// Handle login form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["login"])) {
    $email = $_POST["email"];
    $password = $_POST["password"];

    // Prepared statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? AND status = 'Active'");
    $stmt->bind_param("s", $email); // Bind email parameter to the prepared statement
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        
        if (password_verify($password, $row["password"])) {
            $_SESSION["user_id"] = $row["user_id"];
            $_SESSION["full_name"] = $row["full_name"];
            header("Location: index.php"); // Redirect to homepage after login
            exit();
        } else {
            $error = "Invalid email or password!";
        }
    } else {
        $error = "Account not found or not activated.";
    }

    // Close statement
    $stmt->close();
}

// Handle signup form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["signup"])) {
    $fullname = $_POST["fullname"];
    $email = $_POST["email"];
    $password = password_hash($_POST["password"], PASSWORD_BCRYPT);
    $dob = $_POST["dob"];
    $token = md5(rand()); // Email verification token

    // Check if email exists using prepared statement
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $signup_error = "Email already registered!";
    } else {
        // Insert new user
        $stmt = $conn->prepare("INSERT INTO users (username, email, password, dob, status, token) 
                                VALUES (?, ?, ?, ?, 'Pending', ?)");
        $stmt->bind_param("sssss", $fullname, $email, $password, $dob, $token);

        if ($stmt->execute()) {
            $signup_success = "Registration successful! Check your email to verify.";
        } else {
            $signup_error = "Error: " . $stmt->error;
        }
    }

    // Close statement
    $stmt->close();
}
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shopaholics - Login & Sign Up</title>
    <link rel="stylesheet" href="CSS/styles.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">
</head>
<body>
    <!-- HEADER & NAVIGATION -->
    <header>
        <h3 class="promo"> USE CODE [NEW2025] FOR EXTRA UP TO 20% SKINCARE PRODUCTS </h3>
        <h1 class="logo">SHOPAHOLICS</h1>
    </header>

    <!-- NAVIGATION MENU -->
    <nav>
        <form action="search.php" method="get" class="search-bar">
            <input type="text" name="q" placeholder="Search products, brands..." required>
            <button type="submit"><i class="fas fa-search"></i></button>
        </form>
        <ul>
            <?php
            $menu_items = [
                "Home Page" => "index.php",
                "Home" => "home.php",
                "Technology" => "technology.php",
                "Skincare" => "skincare.php",
                "Makeup" => "makeup.php"
            ];
            foreach ($menu_items as $name => $link) {
                echo "<li><a href='" . htmlspecialchars($link) . "'>" . htmlspecialchars($name) . "</a></li>";
            }
            ?>
        </ul>
        <div class="header-icons">
            <div class="country-selector">
                <img src="IMG/eu-flag.png" alt="EU Flag">
            </div>
            <a href="signup_login.php">
                <i class="fas fa-user"></i>
            </a>
            <i class="fas fa-heart"></i>
            <div class="cart">
                <i class="fas fa-shopping-cart"></i>
                <span class="cart-count">0</span>
            </div>
        </div>
    </nav>

    <!-- AUTHENTICATION FORMS -->
    <div class="auth-container">
        <div class="form-box" id="login-box">
            <h2>Login</h2>
            <?php if (!empty($error)) echo "<p class='error'>$error</p>"; ?>
            <form action="" method="POST">
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" name="login" class="auth-button">Login</button>
                <p>Don't have an account? <a href="#" onclick="showSignup()">Sign Up</a></p>
            </form>
        </div>

        <div class="form-box hidden" id="signup-box">
            <h2>Sign Up</h2>
            <?php if (!empty($signup_error)) echo "<p class='error'>$signup_error</p>"; ?>
            <?php if (!empty($signup_success)) echo "<p class='success'>$signup_success</p>"; ?>
            <form action="" method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="date" name="dob" required>
                <button type="submit" name="signup" class="auth-button">Sign Up</button>
                <p>Already have an account? <a href="#" onclick="showLogin()">Login</a></p>
            </form>
        </div>
    </div>

    <script src="JS/auth.js"></script>
</body>
</html>
