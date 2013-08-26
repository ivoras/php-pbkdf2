<?php
require_once('pbkdf2.php');

$h = PBKDF2::create_hash('helloworld');
echo "$h\nlen=".strlen($h)."\n";
if (!PBKDF2::validate_password('helloworld', $h))
    die("Cannot verify password!\n");
echo "ok\n";

PBKDF2::run_tests();

