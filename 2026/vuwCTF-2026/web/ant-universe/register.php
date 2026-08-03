<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    header("Location: /register.php", true, 503);
    exit();
    if (!key_exists("username", $_POST) || !key_exists("password", $_POST)) {
        header("Location: /register.php", true, 400);
        exit();
    }
    
    if (mb_strlen($_POST["username"]) > 40) {
        header("Location: /register.php", true, 400);
        exit();
    }

    require "database.php";

    $query = "SELECT localtimestamp FROM users;";
    ($result = pg_query($dbconn, $query)) or
        die("Query failed: " . pg_last_error());

    $date = pg_fetch_all($result, PGSQL_ASSOC);
    if (!$date) {
        header("Location: /register.php", true, 500);
        exit();
    } else {
        $date = $date[0]["localtimestamp"];
    }

    $query =
        "INSERT INTO users (username, date_joined, password) VALUES ($1, $2, $3);";
    ($result = pg_query_params($dbconn, $query, [
        $_POST["username"],
        $date,
        password_hash(
            json_encode([$date, $_POST["username"], $_POST["password"]]),
            PASSWORD_BCRYPT,
        ),
    ])) or die("Query failed: " . pg_last_error());

    $user = pg_fetch_all($result, PGSQL_ASSOC);

    if (pg_result_status($result) == PGSQL_COMMAND_OK) {
        header("Location: /login.php", true);
    } else {
        header("Location: /register.php", true, 400);
    }

    pg_free_result($result);
    pg_close($dbconn);
    exit();
} ?>
<!doctype html>
<html>
    <head>
        <link rel="stylesheet" href="static/style.css">
    </head>
    <body>
        <?php include "header.php" ?>
        <div class="post-container" id="user-page-root">
            <h1 style="padding-bottom: 0;">Register</h1>
            <p style="margin-bottom: 0.5rem;">Registrations are disabled as of 1999-12-25 for defensive purposes</p>
            <form method="post">
                <label for="username">Username</label><br>
                <input name="username" type="text" required><br>
                <label for="password">Password</label><br>
                <input name="password" type="password" required><br>
                <input type="submit" value="Register">
            </form>
        </div>
    </body>
</html>
