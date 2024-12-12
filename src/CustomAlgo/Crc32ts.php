<?php

namespace Furbyus\Hashing\CustomAlgo;

use Furbyus\Hashing\BinaryUtils;
use Furbyus\Hashing\Crc\Crc;
use Furbyus\Hashing\Crc\CrcFinalXor;
use Furbyus\Hashing\Crc\CrcInitialValue;
use Furbyus\Hashing\Crc\CrcPolynomials;

class Crc32ts implements CustomAlgo
{
    public function __construct(private string $data)
    {
    }

    public function getHash(bool $binary = false): string
    {
        $strArray = str_split($this->data);
        $byteArray = [];
        array_map(function ($stringChar) use (&$byteArray) {
            $byteArray[] = ord($stringChar);
        }, $strArray);
        $bin = Crc::crcSum($byteArray, 32, CRCPolynomials::CRC_32_TS, CRCInitialValue::CRC_32_TS, CRCFinalXor::CRC_32_TS);
        if ($binary) {
            return $bin;
        }
        $chars = BinaryUtils::decToByteArray($bin);
        return array_reduce($chars, function ($carry, $char) {
            return $carry . dechex($char);
        }, "");
    }

}