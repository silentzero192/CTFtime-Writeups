<!doctype html>
<html>
    <head>
        <link rel="stylesheet" href="static/style.css">
    </head>
    <body>
        <?php include "header.php" ?>
        <div class="border-1">
            <div class="border-2">
                <div class="border-3">
                    <h1>ants ants ants</h1>
                    <p>
                        when you're a ant and you wake up in an awesome mood,
                        about to drive your son to school, only to discover that
                        you left the lights on in the car last night so your
                        battery is drained
                    </p>
                    <img src="static/line.svg" />
                </div>
            </div>
        </div>
        <?php
        require "database.php";

        function findchildposts($results, $parent, $prefix)
        {
            foreach ($results as $post) {
                if ($post["parent"] == $parent) {
                    echo "$prefix<div class=\"post-container\">\n";
                    echo "$prefix\t<p class=\"post-username\">\n\t\t$prefix<a href=\"user.php?u=" . $post["id"] . "\">".$post["username"]."</a>\n\t\t$prefix<span class=\"post-timestamp\">" . $post["utc_time"] .
                        "</span>\n\t$prefix</p>\n";
                    echo $prefix .
                        "\t<p class=\"post-body\">" .
                        $post["message"] .
                        "</p>\n";
                    findchildposts($results, $post["pid"], $prefix . "\t");
                    echo $prefix . "</div>\n";
                }
            }
        }

        $query =
            "SELECT posts.id as pid, posts.parent, posts.utc_time, posts.message, users.username, users.id FROM posts INNER JOIN users ON posts.author = users.id;";
        ($result = pg_query($dbconn, $query)) or
            die("Query failed: " . pg_last_error());

        $results = pg_fetch_all($result, PGSQL_ASSOC);

        findchildposts($results, null, "");

        pg_free_result($result);
        pg_close($dbconn);
        ?>
    </body>
</html>
