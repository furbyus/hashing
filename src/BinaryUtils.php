<?php

namespace Furbyus\Hashing;

class BinaryUtils
{
    public static function endianSwap($value, $bitLength = 32): int|string
    {
        if (PHP_INT_SIZE == 4 || (1 << $bitLength) == 0) {
            if(function_exists("gmp_intval")){
                return self::gmpEndianSwap($value, $bitLength);
            }
            if(function_exists("bcdiv")){
                return self::gmpEndianSwap($value, $bitLength);
            }
            throw new \InvalidArgumentException("Cannot handle bigInt calculations, the value Exceeds the PHP_IN_MAX value and there are no mathematic libraries, neither GMP nor Bc Math  ");
        }
        // Asegurarse de que el valor está dentro del rango permitido
        $maxValue = (1 << $bitLength) - 1;
        if ($value < 0 || $value > $maxValue) {
            throw new \InvalidArgumentException("El valor está fuera del rango para $bitLength bits.");
        }

        // Calcular la cantidad de bytes
        $byteCount = $bitLength / 8;

        // Crear un array de bytes en big-endian (orden natural)
        $bytes = [];
        for ($i = 0; $i < $byteCount; $i++) {
            $bytes[] = ($value >> (8 * ($byteCount - $i - 1))) & 0xFF;
        }

        // Revertir el orden de los bytes para cambiar el endianness
        $bytes = array_reverse($bytes);

        // Reconstruir el valor desde los bytes invertidos
        $swappedValue = 0;
        for ($i = 0; $i < $byteCount; $i++) {
            $swappedValue |= ($bytes[$i] << (8 * ($byteCount - $i - 1)));
        }

        return $swappedValue;
    }

    public static function gmpEndianSwap($value, $bitLength = 64): int|string
    {
        $maxValue = gmp_sub(gmp_pow(2, $bitLength), 1); // 2^bitLength - 1
        if (gmp_cmp($value, 0) < 0 || gmp_cmp($value, $maxValue) > 0) {
            throw new \InvalidArgumentException("El valor está fuera del rango para $bitLength bits.");
        }

        // Calcular la cantidad de bytes
        $byteCount = $bitLength / 8;

        // Crear un array de bytes en big-endian (orden natural)
        $bytes = [];
        for ($i = 0; $i < $byteCount; $i++) {
            $shiftedValue = gmp_div_q($value, gmp_pow(2, 8 * ($byteCount - $i - 1)));
            $bytes[] = gmp_intval(gmp_and($shiftedValue, 0xFF)); // Extrae el byte actual
        }

        // Revertir el orden de los bytes para cambiar el endianness
        $bytes = array_reverse($bytes);

        // Reconstruir el valor desde los bytes invertidos
        $swappedValue = gmp_init(0);
        for ($i = 0; $i < $byteCount; $i++) {
            $swappedValue = gmp_add(
                $swappedValue,
                gmp_mul($bytes[$i], gmp_pow(2, 8 * ($byteCount - $i - 1)))
            );
        }

        return (gmp_cmp(PHP_INT_MAX, $swappedValue)) ? gmp_strval($swappedValue) : gmp_intval($swappedValue);
    }
    public static function bcEndianSwap($value, $bitLength = 64){
        $maxValue = bcsub(bcpow('2', (string)$bitLength), '1'); // 2^bitLength - 1
        if (bccomp($value, '0') < 0 || bccomp($value, $maxValue) > 0) {
            throw new \InvalidArgumentException("El valor está fuera del rango para $bitLength bits.");
        }

        // Calcular la cantidad de bytes
        $byteCount = $bitLength / 8;

        // Crear un array de bytes en big-endian (orden natural)
        $bytes = [];
        for ($i = 0; $i < $byteCount; $i++) {
            // Obtener el byte correspondiente
            $shiftedValue = bcdiv($value, bcpow('2', (string)(8 * ($byteCount - $i - 1))), 0);
            $bytes[] = bcmod($shiftedValue, '256'); // Extrae el byte actual
        }

        // Revertir el orden de los bytes para cambiar el endianness
        $bytes = array_reverse($bytes);

        // Reconstruir el valor desde los bytes invertidos
        $swappedValue = '0';
        for ($i = 0; $i < $byteCount; $i++) {
            $swappedValue = bcadd(
                $swappedValue,
                bcmul($bytes[$i], bcpow('2', (string)(8 * ($byteCount - $i - 1))))
            );
        }

        return $swappedValue; // Devuelve como cadena para garantizar precisión
    }

    public static function decToByteArray(int $value, $bitLength = 32): array
    {

        $mask = (1 << $bitLength) - 1;
        if($mask < $value){
            throw new \OutOfRangeException("Cannot handle the value $value within $bitLength bits!");
        }
        $value &= $mask;

        $byteCount = ceil($bitLength / 8);

        $byteArray = [];
        for ($i = 0; $i < $byteCount; $i++) {
            $byteArray[] = ($value >> (8 * ($byteCount - $i - 1))) & 0xFF;
        }

        return $byteArray;
    }

}