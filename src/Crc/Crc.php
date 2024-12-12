<?php

namespace Furbyus\Hashing\Crc;

use Furbyus\Hashing\BinaryUtils;
use Furbyus\Hashing\Hash;

class Crc extends Hash
{

    public static function crcSum($data, $bitLengh, $polynomial = 0x04C11DB7, $initialValue = 0x00000000, $xorOut = 0x00000000, $reflectedOut = true)
    {
        $crc = $initialValue;
        $upperByteSelector = $bitLengh - 8;
        $msbMask = 1 << ($bitLengh - 1);

        foreach ($data as $p => $byte) {
            $crc ^= ($byte << $upperByteSelector); // XOR el byte en la parte alta del CRC
            for ($i = 0; $i < 8; $i++) {
                if ($crc & $msbMask) {
                    $crc = ($crc << 1) ^ $polynomial; // Aplica el polinomio si el MSB es 1
                } else {
                    $crc <<= 1; // Simplemente desplaza si el MSB es 0
                }
            }
        }
        $mask = (1 << $bitLengh) - 1;
        $crc &= $mask; // Asegura que sea un valor de $bitLengh bits sin signo
        $result = $crc ^ $xorOut;// Aplica XOR-out (si es necesario)
        return ($reflectedOut ? BinaryUtils::endianSwap($result, $bitLengh) : $result); // Cambia Endian
    }


}