<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shopaholics - Home</title>
    <link rel="stylesheet" href="CSS/styles.css" >
    <link rel="stylesheet" href="CSS/index.css" >
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">


</head>
<?php
include 'db_connect.php'; // This file connects to MySQL
?>

<body>
    <!-- HEADER & NAVIGATION -->
    <header>
        <h3  class="promo"> USE CODE [NEW2025] FOR EXTRA UP TO 20% SKINCARE PRODUCTS </h3>
        
    
    </header>
    
      <!-- NAVIGATION MENU WITH SEARCH BAR -->
      <nav>
    <div class="logo">
         <h1> <a href ="index.php"> SHOPAHOLICS <a/> </h1>
    </div>
    
    <ul class="nav-menu">
        <?php
        $menu_items = [
            "Home Page  " => "index.php",
            "Home" => "homeStore.php",
            "Technology" => "technology.php",
            "Skincare" => "skincare.php",
            "Makeup" => "makeup.php"
        ];
        foreach ($menu_items as $name => $link) {
            echo "<li><a href='" . htmlspecialchars($link) . "'>" . htmlspecialchars($name) . "</a></li>";
        }
        ?>
    </ul>

    <div class="nav-right">
        <form action="#" method="get" class="search-bar">
            <input type="text" name="q" placeholder="Search" required>
            <button type="submit"><i class="fas fa-search"></i></button>
        </form>

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
    </div>
</nav>
    
    
       <!-- HERO SECTION -->
       <section class="hero">
        <img src="IMG/homepage_banner.jpg" alt="Shop the Best Products" class="hero-image">
        <div class="hero-content">
            <h2>Discover Your Favorites</h2>
            <p>Shop the best in Home, skincare, makeup, and tech today!</p>
        </div>

    </section>
    

    <!-- IMAGE SLIDER SECTION -->
<section class="image-slider">
<div class="slider-container">
        <div class="slider">
            <div class="slide"><img src="HomeIMG/hp7_banner.jpg" alt="Slide 1"></div>
            <div class="slide"><img src="HOMEIMG/hp6_banner.jpg" alt="Slide 2"></div>
            <div class="slide"><img src="HOMEIMG/hp3_banner.jpg" alt="Slide 2"></div>
            <div class="slide"><img src="HOMEIMG/HP_BANNER.jpg" alt="Slide 2"></div>

        </div>
        <button class="prev" onclick="moveSlide(-1)">&#10094;</button>
        <button class="next" onclick="moveSlide(1)">&#10095;</button>
    </div>
</section>

    <!-- CATEGORY SECTION -->
    <section class="categories">
        <h2>Shop by Category</h2>
        
        <div class="category-container">

            <div class="category">
                <a href="technology.php">
                    <img src="IMG/tech_banner3.jpg" alt="Technology"><p>Technology</p>
                </a>
            </div>
            <div class="category">
                <a href="skincare.php"> 
                    <img src="IMG/skincare_banner1.jpg" alt="Skincare"><p>Skincare</p> 
                </a>    
           </div>
            <div class="category">
                <a href="homeStore.php" > 
                    <img src="IMG/home_banner2.jpg" alt="Home"><p>Home</p>
                </a>
                </div>
            <div class="category">
                <a href="makeup.php"> 
                    <img src="HOMEIMG/makeup_banner.jpg" alt="Home"><p>Makeup</p>
                </a>
                </div>

        </div>
    </section>
    
    <!-- FEATURED PRODUCTS -->
    <section class="featured-products" id="featured">
        <h2>Featured Products</h2>
        <hr style="border-color: brown border-width: 5px;">
        <div class="product-container">
    <?php
    include 'db_connect.php'; // Ensure database connection is included

    $sql = "SELECT * FROM Products LIMIT 4"; // Fetch 4 featured products
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            echo "<div class='product-card'>";
            echo "<img src='IMG/" . htmlspecialchars($row['image']) . "' alt='" . htmlspecialchars($row['name']) . "'>";
            echo "<h3>" . htmlspecialchars($row['name']) . "</h3>";
            echo "<p class='product-price'>€" . htmlspecialchars($row['price']) . "</p>";
            echo "<button class='add-to-bag'>Add to Bag</button>";
            echo "</div>";
        }
    } else {
        echo "<p>No products found.</p>";
    }
    ?>
</div>

    </section>

    <!-- FOOTER -->
     <footer>
    <div class="footer-container">
        <div class="footer-section">
            <h3>About Us</h3>
            <p>Shopaholics - Your go-to store for tech, skincare, and more.</p>

        </div>
        <div class="footer-section">
            <h3>Quick Links</h3>
            <ul>
                <li><a href="home.php">Home</a></li>
                <li><a href="technology.php">Technology</a></li>
                <li><a href="skincare.php">Skincare</a></li>
                <li><a href="makeup.php">Makeup</a></li>
            </ul>
        </div>
        <div class="footer-section">
            <h3> Meet yout Owners </h3>
            <p> Cheryl Donga </p>
            <p> Mireille Aka </p>
            <p> Vivien Obi </p>
        </div>
        <div class="footer-section">
            <h3>Follow Us</h3>
            <div class="social-icons">
                <a href="#"><i class="fab fa-facebook"></i></a>
                <a href="#"><i class="fab fa-instagram"></i></a>
                <a href="#"><i class="fab fa-twitter"></i></a>
                <a href="#"><i class="fab fa-tiktok"></i></a>
            </div>
        </div>
    </div>
    <p class="footer-bottom">&copy; 2025 Shopaholics. All rights reserved.</p>
</footer>
<script src="JS/imageslider.js"></script>

</body>
</html>