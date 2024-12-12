### Furbyus\Hashing
This library is intended to wrap and extend the hash(), hash_hmac() and other PHP functions like crc() or md5() in an OOP paradigm, including contructor or static method makers way.

Example:
````PHP
<?php

use Furbyus\Hashing\Hash;
use Furbyus\Hashing\Enum\HashAlgo;

/**
* Generation of non-cryptographic Hash
* See Furbyus\Hashing\Enum\HashAlgo for the entire list of available Algorithms
* there will be minimum all the algos returned by hash_algos() PHP function, plus some more (Ex. CRC32TS)
*/
$hashValue = Hash::make("My data", HashAlgo::MURMUR3A);
// OR
$hashValue = Hash::make("My data", HashAlgo::CRC32);

/**
* Generation of cryptographic Hash
*/
$secretKey = "someSecret";

$hashValue = Hash::make("My data", HashAlgo::SHA512, $secretKey);
// OR
$hashValue = Hash::make("My data", HashAlgo::RIPEMD256, $secretKey);

/**
* Comparing cryptographic Hash (Validating a known Hash vs the user inputs)
*/

$result = Hash::compare($knownHash, $data, $algorithm, $key); // returns True only if the $knownHash have been generated with the same $data, $algorithm and $key provided. False otherwise
// Real world usage example | Values faked ;) 
$savedHashedPassword = "dkljnscfdajklnsacdljnvscdjln"; 
$data = "user=userName";
$secret = "userPassword";

if(!Hash::compare($savedHashedPassword, $data, HashAlgo::SHA512, $secret)){
    throw new \Exception("User & Password combination invalid!");
}else{
    // User authenticated by username & password!
}