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
        <h3  class="promo"> USE CODE [NEW2025] FOR EXTRA UP TO 20% SKINCARE PRODUCTS </h3>
        <h1 class="logo">SHOPAHOLICS</h1>
    
    </header>
    
      <!-- NAVIGATION MENU WITH SEARCH BAR -->
      <nav>
        <form action="#" method="get" class="search-bar">
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
    
    <div class="auth-container">
        <div class="form-box" id="login-box">
            <h2>Login</h2>
            <?php if (!empty($error)) echo "<p class='error'>$error</p>"; ?>
            <form action="index.php" method="POST">
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="auth-button">Login</button>
                <p>Don't have an account? <a href="#" onclick="showSignup()">Sign Up</a></p>
            </form>
        </div>

        <div class="form-box hidden" id="signup-box">
            <h2>Sign Up</h2>
            <form action="signup.php" method="POST">
                <input type="text" name="fullname" placeholder="Full Name" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="auth-button">Sign Up</button>
                <p>Already have an account? <a href="#" onclick="showLogin()">Login</a></p>
            </form>
        </div>
    </div>

    <script src="JS/auth.js"></script>
</body>
</html>
