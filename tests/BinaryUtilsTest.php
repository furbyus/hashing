<?php


use Furbyus\Hashing\BinaryUtils;

final class BinaryUtilsTest extends \PHPUnit\Framework\TestCase
{
    public function testCanConvertDecimalIntToByteArray(): void
    {
        $intValue = 255896;
        $byteArrayExpectedValue = [0x3, 0xE7, 0x98];
        $byteArrayResult = BinaryUtils::decToByteArray($intValue, 24);
        $this->assertSame($byteArrayExpectedValue, $byteArrayResult);
    }

    public function testCannotConvertDecimalToTiniestByteArray(): void
    {
        $intValue = pow(2, 16);
        $this->expectException(OutOfRangeException::class);
        BinaryUtils::decToByteArray($intValue, 16);
    }

    public function testCanConvertMaxDecimalToExactSizeByteArray(): void
    {
        $intValue = pow(2, 16) - 1;
        $byteArrayExpectedValue = [0xFF, 0xFF];
        $byteArrayResult = BinaryUtils::decToByteArray($intValue, 16);
        $this->assertSame($byteArrayExpectedValue, $byteArrayResult);
    }

    public function testCanConvertZeroDecimalToByteArray(): void
    {
        $intValue = 0;
        $byteArrayExpectedValue = [0x00];
        $byteArrayResult = BinaryUtils::decToByteArray($intValue, 8);
        $this->assertSame($byteArrayExpectedValue, $byteArrayResult);
    }
}