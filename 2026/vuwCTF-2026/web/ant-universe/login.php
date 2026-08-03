<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!key_exists("username", $_POST) || !key_exists("password", $_POST)) {
        error_log("Field missing", 0, "php://stdout");
        header("Location: /login.php", true, 400);
        exit();
    }

    require "database.php";

    $query = "SELECT * FROM users WHERE username = $1;";
    ($result = pg_query_params($dbconn, $query, [$_POST["username"]])) or
        die("Query failed: " . pg_last_error());

    $user = pg_fetch_all($result, PGSQL_ASSOC);

    pg_free_result($result);
    pg_close($dbconn);

    if ($user) {
        if (
            !key_exists("date_joined", $user[0]) ||
            !key_exists("username", $user[0]) ||
            !key_exists("password", $user[0])
        ) {
            header("Location: /login.php", true, 400);
            exit();
        }
        $token = [
            $user[0]["date_joined"],
            $_POST["username"],
            $_POST["password"],
        ];
        setcookie(
            "token",
            json_encode($token),
            time() + 86400,
            "/",
            secure: true,
        );
        header("Location: /user.php?u=" . $user[0]["id"]);
        exit();
    }
} ?>
<!doctype html>
<html>
    <head>
        <link rel="stylesheet" href="static/style.css">
    </head>
    <body>
        <?php include "header.php" ?>
        <div class="post-container" id="user-page-root">
            <h1 style="padding-bottom: 0;">Login</h1>
            <form method="post">
                <label for="username">Username</label><br>
                <input name="username" type="text" required> <br>
                <label for="password">Password</label><br>
                <input name="password" type="password" required> <br>
                <input type="submit" value="Login">
            </form>
        </div>
    </body>
</html>
