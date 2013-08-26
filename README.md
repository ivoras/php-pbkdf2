php-pbkdf2
==========

An implementation of PBKDF2 in PHP. Usage:

```php
require_once('pbkdf2.php');

$h = PBKDF2::create_hash('helloworld');
echo "$h\n";
if (!PBKDF2::validate_password('helloworld', $h))
    die("Cannot verify password!\n");
echo "ok\n";
```

Constants in the PBKDF2 class can be tweaked to change the default PBKDF2 parameters.
