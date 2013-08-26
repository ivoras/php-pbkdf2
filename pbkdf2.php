<?php
/*
 * Password hashing with PBKDF2.
 * Author: havoc AT defuse.ca
 * www: https://defuse.ca/php-pbkdf2.htm
 * Wrapped in a class and converted to mb_* API by: ivoras
 */

class PBKDF2 {

    // These constants may be changed without breaking existing hashes.
    const PBKDF2_HASH_ALGORITHM = "sha256";
    const PBKDF2_ITERATIONS = 2003;
    const PBKDF2_SALT_BYTES = 9;    // If the *_BYTES are a multiple of 3, they will fit neatly with base64
    const PBKDF2_HASH_BYTES = 21;

    const HASH_SECTIONS = 4;
    const HASH_ALGORITHM_INDEX = 0;
    const HASH_ITERATION_INDEX = 1;
    const HASH_SALT_INDEX = 2;
    const HASH_PBKDF2_INDEX = 3;

    static function create_hash($password)
    {
        // format: algorithm:iterations:salt:hash
        $salt = base64_encode(mcrypt_create_iv(self::PBKDF2_SALT_BYTES, MCRYPT_DEV_URANDOM));
        return self::PBKDF2_HASH_ALGORITHM . ":" . self::PBKDF2_ITERATIONS . ":" .  $salt . ":" . 
            base64_encode(self::pbkdf2f(
                self::PBKDF2_HASH_ALGORITHM,
                $password,
                $salt,
                self::PBKDF2_ITERATIONS,
                self::PBKDF2_HASH_BYTES,
                true
            ));
    }

    static function validate_password($password, $good_hash)
    {
        $params = explode(":", $good_hash);
        if(count($params) < self::HASH_SECTIONS)
           return false; 
        $pbkdf2 = base64_decode($params[self::HASH_PBKDF2_INDEX]);
        return self::slow_equals(
            $pbkdf2,
            self::pbkdf2f(
                $params[self::HASH_ALGORITHM_INDEX],
                $password,
                $params[self::HASH_SALT_INDEX],
                (int)$params[self::HASH_ITERATION_INDEX],
                mb_strlen($pbkdf2, 'ISO-8859-1'),
                true
            )
        );
    }

    // Compares two strings $a and $b in length-constant time.
    private static function slow_equals($a, $b)
    {
        $diff = mb_strlen($a, 'ISO-8859-1') ^ mb_strlen($b, 'ISO-8859-1');
        for($i = 0; $i < mb_strlen($a, 'ISO-8859-1') && $i < mb_strlen($b, 'ISO-8859-1'); $i++)
        {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $diff === 0; 
    }

    /*
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $key_length - The length of the derived key in bytes.
     * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $key_length-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     */
    private static function pbkdf2f($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        $algorithm = strtolower($algorithm);
        if(!in_array($algorithm, hash_algos(), true))
            die('PBKDF2 ERROR: Invalid hash algorithm.');
        if($count <= 0 || $key_length <= 0)
            die('PBKDF2 ERROR: Invalid parameters.');

        $hash_length = mb_strlen(hash($algorithm, "", true), 'ISO-8859-1');
        $block_count = ceil($key_length / $hash_length);

        $output = "";
        for($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if($raw_output)
            return mb_substr($output, 0, $key_length, 'ISO-8859-1');
        else
            return bin2hex(mb_substr($output, 0, $key_length, 'ISO-8859-1'));
    }


    private static function assert_true($result, $msg)
    {
        if($result === true)
            echo "PASS: [$msg]\n";
        else
            echo "FAIL: [$msg]\n";
    }

    static function run_tests() {
        // The following test vectors were taken from RFC 6070.
        // https://www.ietf.org/rfc/rfc6070.txt

        $pbkdf2_vectors = array(
            array(
                'algorithm' => 'sha1', 
                'password' => "password", 
                'salt' => "salt", 
                'iterations' => 1, 
                'keylength' => 20, 
                'output' => "0c60c80f961f0e71f3a9b524af6012062fe037a6" 
                ),
            array(
                'algorithm' => 'sha1', 
                'password' => "password", 
                'salt' => "salt", 
                'iterations' => 2, 
                'keylength' => 20, 
                'output' => "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
                ),
            array(
                'algorithm' => 'sha1', 
                'password' => "password", 
                'salt' => "salt", 
                'iterations' => 4096, 
                'keylength' => 20, 
                'output' => "4b007901b765489abead49d926f721d065a429c1"
                ),
            array(
                'algorithm' => 'sha1', 
                'password' => "passwordPASSWORDpassword", 
                'salt' => "saltSALTsaltSALTsaltSALTsaltSALTsalt", 
                'iterations' => 4096, 
                'keylength' => 25, 
                'output' => "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
                ), 
            array(
                'algorithm' => 'sha1', 
                'password' => "pass\0word", 
                'salt' => "sa\0lt", 
                'iterations' => 4096, 
                'keylength' => 16, 
                'output' => "56fa6aa75548099dcc37d7f03425e0c3"
                ),            
        );

        foreach($pbkdf2_vectors as $test) {
            $realOut = self::pbkdf2f(
                $test['algorithm'],
                $test['password'],
                $test['salt'],
                $test['iterations'],
                $test['keylength'],
                false
            );

            self::assert_true($realOut === $test['output'], "PBKDF2 vector");
        }

        $good_hash = self::create_hash("foobar");
        self::assert_true(self::validate_password("foobar", $good_hash), "Correct password");
        self::assert_true(self::validate_password("foobar2", $good_hash) === false, "Wrong password");

        $h1 = explode(":", self::create_hash(""));
        $h2 = explode(":", self::create_hash(""));
        self::assert_true($h1[self::HASH_PBKDF2_INDEX] != $h2[self::HASH_PBKDF2_INDEX], "Different hashes");
        self::assert_true($h1[self::HASH_SALT_INDEX] != $h2[self::HASH_SALT_INDEX], "Different salts");

        self::assert_true(self::slow_equals("",""), "Slow equals empty string");
        self::assert_true(self::slow_equals("abcdef","abcdef"), "Slow equals normal string");

        self::assert_true(self::slow_equals("aaaaaaaaaa", "aaaaaaaaab") === false, "Slow equals different");
        self::assert_true(self::slow_equals("aa", "a") === false, "Slow equals different length 1");
        self::assert_true(self::slow_equals("a", "aa") === false, "Slow equals different length 2");

        echo "Example hash: $good_hash\n";
    }

}
