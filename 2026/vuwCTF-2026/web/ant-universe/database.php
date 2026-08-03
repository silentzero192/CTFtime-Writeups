<?php

$dbinit = false;
$dbconn = pg_connect(
    "host=db dbname=antsantsants user=antmin password=1L0V3MYANT5P455W0RD",
) or die("failed to connect to database: ". pg_last_error());