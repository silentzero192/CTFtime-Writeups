<?php
require "database.php";

if (!array_key_exists("u", $_GET)) {
    header("Location: /");
    die("No id provided");
}
$uid = intval($_GET["u"]);

$query = "SELECT username, password, date_joined FROM users WHERE id = $1;";
($result = pg_query_params($dbconn, $query, [$uid])) or
    die("Query failed: " . pg_last_error());

$name = pg_fetch_all($result, PGSQL_ASSOC);

$groups = [];

if ($name) {
    $password = $name[0]["password"];
    $date_joined = $name[0]["date_joined"];
    $name = $name[0]["username"];
    $query =
        "SELECT g.name, go.id as owner_id, go.username as owner_username from group_members gm LEFT JOIN groups g ON gm.group_id = g.id LEFT JOIN users go ON g.owner = go.id WHERE gm.user_id = $1;"; // i love sql

    pg_free_result($result);

    ($result = pg_query_params($dbconn, $query, [$uid])) or
        die("Query failed: " . pg_last_error());
    $groups = pg_fetch_all($result, PGSQL_ASSOC);
}

pg_free_result($result);
?>
<!doctype html>
<html>
    <head>
        <link rel="stylesheet" href="static/style.css">
    </head>
    <body>
        <?php include "header.php"; ?>
        <div class="post-container" id="user-page-root">
            <?php if ($name == false) {
                echo "<h1 id=\"user-title\">Unknown user</h1>";
            } else {
                echo "<h1 id=\"user-title\">$name</h1>\n";
                echo "<p>Joined $date_joined</p>\n";

                if (count($groups) > 0) {
                    echo "<p>Groups:</p>\n<ul class=\"grouplist\">";
                    foreach ($groups as $group) {
                        echo "\n\t<li>" . $group["name"];
                        if ($uid == $group["owner_id"]) {
                            echo "<span class=\"groupowner\">(owner)</span></li>";
                        } else {
                            echo "<span class=\"groupowner\">(owned by <a href=\"/user.php?u=" .
                                $group["owner_id"] .
                                "\">" .
                                $group["owner_username"] .
                                "</a>)</span></li>";
                        }
                    }
                    echo "\n</ul>";
                }

                if (isset($_COOKIE["token"])) {
                    $query =
                        "SELECT password, private_blog FROM users WHERE id = $1;";
                    ($result = pg_query_params($dbconn, $query, [$uid])) or
                        die("Query failed: " . pg_last_error());
                    $hash = pg_fetch_all($result, PGSQL_ASSOC);
                    if ($hash) {
                        $blog = $hash[0]["private_blog"];
                        $hash = $hash[0]["password"];
                        if (password_verify($_COOKIE["token"], $hash)) {
                            echo "<p>" . $blog . "</p>";
                        }
                    }
                }
                pg_close($dbconn);
            } ?>
        </div>
    </body>
</html>
