<?php

use Furbyus\Hashing\Hash;
use Furbyus\Hashing\Enum\HashAlgo;

final class HashTest extends \PHPUnit\Framework\TestCase
{
    private string $testData1 = "String to hash test";
    private function getHashingResult(string $algorithm, string $data): string
    {
        return Hash::make($data, $algorithm);
    }

    public function testCannotGenerateNonexistentHash(): void
    {
        $this->expectException(\LogicException::class);
        $this->getHashingResult('unsupported-algorithm', $this->testData1);

    }
    public function testCompareDistinctHash(): void
    {
        $knownHash = 'b7608a650d2b2888690530b390463597';
        $result = Hash::compare($knownHash, $this->testData1,HashAlgo::MD2);
        $this->assertSame(false, $result);
    }
    public function testCompareEqualHash(): void
    {
        $knownHash = 'b7608a650d1b2888690530b390463597';
        $result = Hash::compare($knownHash, $this->testData1,HashAlgo::MD2);
        $this->assertSame(true, $result);
    }

    public function testCanGenerateMd2Hash(): void
    {
        $expectedResult = 'b7608a650d1b2888690530b390463597';
        $result = $this->getHashingResult(HashAlgo::MD2, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateMd4Hash(): void
    {
        $expectedResult = '7c65711d9bebf27e23ea067d74958745';
        $result = $this->getHashingResult(HashAlgo::MD4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateMd5Hash(): void
    {
        $expectedResult = '2cdf7dfd2fea0324f831cbb3a81f2877';
        $result = $this->getHashingResult(HashAlgo::MD5, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha1Hash(): void
    {
        $expectedResult = 'd08be4e662fd89797ad3defc7cefb2b3f4c53d22';
        $result = $this->getHashingResult(HashAlgo::SHA1, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha224Hash(): void
    {
        $expectedResult = 'b2e85b551883aaffbb70b287bdd6e67fef9e23460418a5817f7a8a9a';
        $result = $this->getHashingResult(HashAlgo::SHA224, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha256Hash(): void
    {
        $expectedResult = 'ca72572ba8f938d5a979c0643071df95c2c88b34a44671eccabd65316a0a3a9d';
        $result = $this->getHashingResult(HashAlgo::SHA256, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha384Hash(): void
    {
        $expectedResult = '9986ff061f5e768279bcfc16ee2f613e68f9f0ea241b66b58a8cb9fdf3dafe0b6899cb141d811f7e520837702f51a22f';
        $result = $this->getHashingResult(HashAlgo::SHA384, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha512Hash(): void
    {
        $expectedResult = 'c38f63fce159c94d8ac6afbc01ebdf8fad5315deac637353cf83d07e77ff7bf48855ace1c27f4ae263ba23e450c9241e86631ca0e7a4362c67a3aec88605849c';
        $result = $this->getHashingResult(HashAlgo::SHA512, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha512d224Hash(): void
    {
        $expectedResult = '95fc9f956ac2b92d23499aa55ec8cfa04f589e78663548e6b0cf88e0';
        $result = $this->getHashingResult(HashAlgo::SHA512_224, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha512d256Hash(): void
    {
        $expectedResult = '304bb75669fcfd6f2c0a3486b6ef2c6d35c801d1efed015424270d316754ab18';
        $result = $this->getHashingResult(HashAlgo::SHA512_256, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha3d224Hash(): void
    {
        $expectedResult = 'e126ef0324e8ac70475680cf8a4bd6f36e11adc6bf1d14b5e7fd21f8';
        $result = $this->getHashingResult(HashAlgo::SHA3_224, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha3d256Hash(): void
    {
        $expectedResult = 'f1f3146fb1a5e65911176e61de66c118a82074630e45e2ffaeffe0c471def5ce';
        $result = $this->getHashingResult(HashAlgo::SHA3_256, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha3d384Hash(): void
    {
        $expectedResult = 'b3ae358884d6407a34ecb54d9443f46c02129242864a6234f29d97d65dc17ac8e1de8bfe2d83db12684861707034011f';
        $result = $this->getHashingResult(HashAlgo::SHA3_384, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSha3d512Hash(): void
    {
        $expectedResult = 'fe82e2d54373ba3ed07f5e1a34f0a1acc40ea2915974ed35b0376fdb2ceeb76789f75f81f3b39b06f7bbeac249a3eeb5eda44a660884acf974697bf1c5451467';
        $result = $this->getHashingResult(HashAlgo::SHA3_512, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }

    public function testCanGenerateRipemd128Hash(): void
    {
        $expectedResult = '785e826238ddd39509322c1eae92ade9';
        $result = $this->getHashingResult(HashAlgo::RIPEMD128, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateRipemd160Hash(): void
    {
        $expectedResult = '6c87737155c10f06356c711662a432ad53c757ca';
        $result = $this->getHashingResult(HashAlgo::RIPEMD160, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateRipemd256Hash(): void
    {
        $expectedResult = '03a453639467eb77b2aa3f1d4a24c2d5034a08e67b6d5aaf7c3116a59ce09a78';
        $result = $this->getHashingResult(HashAlgo::RIPEMD256, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateRipemd320Hash(): void
    {
        $expectedResult = 'b3706d3a6d0791d121cb816926d244b2cfe4a21b3be162c898af064e7ac04e17fd1634ce3869148e';
        $result = $this->getHashingResult(HashAlgo::RIPEMD320, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateWhirlpoolHash(): void
    {
        $expectedResult = 'b901b4ccf4902d3b8095d13ccef42ba809923eb341988b8df064681dbd84d6a2ab36c667edc096337f3a07cefc1a496e11ffc804263136e01371c9b85d393de9';
        $result = $this->getHashingResult(HashAlgo::WHIRLPOOL, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateTiger128d3Hash(): void
    {
        $expectedResult = '067df45d7137bbf6023bf7ba92f9a03c';
        $result = $this->getHashingResult(HashAlgo::TIGER128_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateTiger160d3Hash(): void
    {
        $expectedResult = '067df45d7137bbf6023bf7ba92f9a03c9657d0cc';
        $result = $this->getHashingResult(HashAlgo::TIGER160_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateTiger192d3Hash(): void
    {
        $expectedResult = '067df45d7137bbf6023bf7ba92f9a03c9657d0cc3cffb597';
        $result = $this->getHashingResult(HashAlgo::TIGER192_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateTiger128d4Hash(): void
    {
        $expectedResult = '440997f4dcfc368ebc15a186cd1a6d30';
        $result = $this->getHashingResult(HashAlgo::TIGER128_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateTiger160d4Hash(): void
    {
        $expectedResult = '440997f4dcfc368ebc15a186cd1a6d308908a48e';
        $result = $this->getHashingResult(HashAlgo::TIGER160_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateTiger192d4Hash(): void
    {
        $expectedResult = '440997f4dcfc368ebc15a186cd1a6d308908a48e009a28f5';
        $result = $this->getHashingResult(HashAlgo::TIGER192_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSnefruHash(): void
    {
        $expectedResult = '81aeec250596134209d625b3ed69974fac9f69df170246f178d349bdd5f2ced5';
        $result = $this->getHashingResult(HashAlgo::SNEFRU, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateSnefru256Hash(): void
    {
        $expectedResult = '81aeec250596134209d625b3ed69974fac9f69df170246f178d349bdd5f2ced5';
        $result = $this->getHashingResult(HashAlgo::SNEFRU256, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateGostHash(): void
    {
        $expectedResult = '41508e652e658cb8c0cb26d2a5cde84162df3f124c2f8037eae09588c50287cd';
        $result = $this->getHashingResult(HashAlgo::GOST, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateGostCryptoHash(): void
    {
        $expectedResult = '5e95dc65f45519e702bf3b54505974db0a3a25375eba568b79930556f3f7e2ff';
        $result = $this->getHashingResult(HashAlgo::GOST_CRYPTO, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateAdler32Hash(): void
    {
        $expectedResult = '46ed071f';
        $result = $this->getHashingResult(HashAlgo::ADLER32, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateCrc32Hash(): void
    {
        $expectedResult = '953ddc6b';
        $result = $this->getHashingResult(HashAlgo::CRC32, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateCrc32BHash(): void
    {
        $expectedResult = '155fa464';
        $result = $this->getHashingResult(HashAlgo::CRC32B, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateCrc32CHash(): void
    {
        $expectedResult = '2510df76';
        $result = $this->getHashingResult(HashAlgo::CRC32C, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateCrc32TsHash(): void
    {
        $expectedResult = 'ce2d4f9d';
        $result = $this->getHashingResult(HashAlgo::CRC32TS, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateFnv132Hash(): void
    {
        $expectedResult = 'db5e1269';
        $result = $this->getHashingResult(HashAlgo::FNV132, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateFnv1a32Hash(): void
    {
        $expectedResult = '764880e1';
        $result = $this->getHashingResult(HashAlgo::FNV1A32, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateFnv164Hash(): void
    {
        $expectedResult = '30126562cdbfd129';
        $result = $this->getHashingResult(HashAlgo::FNV164, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateFnv1a64Hash(): void
    {
        $expectedResult = '93399337a49813e1';
        $result = $this->getHashingResult(HashAlgo::FNV1A64, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateJoaatHash(): void
    {
        $expectedResult = 'a377c587';
        $result = $this->getHashingResult(HashAlgo::JOAAT, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateMurmur3aHash(): void
    {
        $expectedResult = '7714c44e';
        $result = $this->getHashingResult(HashAlgo::MURMUR3A, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateMurmur3cHash(): void
    {
        $expectedResult = '4b10ee78ee39f73a720fd038423b5418';
        $result = $this->getHashingResult(HashAlgo::MURMUR3C, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateMurmur3fHash(): void
    {
        $expectedResult = '1153d3a817c9c1fb1c3636db164f0cf4';
        $result = $this->getHashingResult(HashAlgo::MURMUR3F, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateXxh32Hash(): void
    {
        $expectedResult = 'e3ceae7a';
        $result = $this->getHashingResult(HashAlgo::XXH32, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateXxh64Hash(): void
    {
        $expectedResult = '1a350c803f1e11cf';
        $result = $this->getHashingResult(HashAlgo::XXH64, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateXxh3Hash(): void
    {
        $expectedResult = '854fac2827b90573';
        $result = $this->getHashingResult(HashAlgo::XXH3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateXxh128Hash(): void
    {
        $expectedResult = '769083357860283696809053cad495e8';
        $result = $this->getHashingResult(HashAlgo::XXH128, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval128d3Hash(): void
    {
        $expectedResult = 'd5e83b953df15aea063c8a62f0bdc5c6';
        $result = $this->getHashingResult(HashAlgo::HAVAL128_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval160d3Hash(): void
    {
        $expectedResult = '6cb954c7037d958f062d441b7fcef0eb00a5624b';
        $result = $this->getHashingResult(HashAlgo::HAVAL160_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval192d3Hash(): void
    {
        $expectedResult = 'e9e89cc3ceabcd700a795d9bef1c1741db21304d47c6a423';
        $result = $this->getHashingResult(HashAlgo::HAVAL192_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval224d3Hash(): void
    {
        $expectedResult = 'ea7a82593c639d1b689af7746d66e4ec5541dcdfd441760bec9305ad';
        $result = $this->getHashingResult(HashAlgo::HAVAL224_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval256d3Hash(): void
    {
        $expectedResult = '53ef9da9828fe5961e18f0fd36bd91ff29034ee468ab84858091a165a839f88b';
        $result = $this->getHashingResult(HashAlgo::HAVAL256_3, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval128d4Hash(): void
    {
        $expectedResult = '7e1f30dd34a02de5d28067b0b49cd3ec';
        $result = $this->getHashingResult(HashAlgo::HAVAL128_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval160d4Hash(): void
    {
        $expectedResult = 'baf4ad899f0affd92a91a8b3d112b9da0bc4f28a';
        $result = $this->getHashingResult(HashAlgo::HAVAL160_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval192d4Hash(): void
    {
        $expectedResult = '59e3d979e4d34a2082c753981f331c566a34aa423b08a44a';
        $result = $this->getHashingResult(HashAlgo::HAVAL192_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval224d4Hash(): void
    {
        $expectedResult = 'a534984f99aa505a20a1c18cd68e9af56b727fd1fc00d2da863b43e8';
        $result = $this->getHashingResult(HashAlgo::HAVAL224_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval256d4Hash(): void
    {
        $expectedResult = '6be8e65d3bbc87256b6627a7bacc1e81c5a6b2e46719b3f96e6e61b3962fbd8b';
        $result = $this->getHashingResult(HashAlgo::HAVAL256_4, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval128d5Hash(): void
    {
        $expectedResult = 'cd4f29d2bd59502f3abaad4249165ce2';
        $result = $this->getHashingResult(HashAlgo::HAVAL128_5, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval160d5Hash(): void
    {
        $expectedResult = '4a3e4a3cb7c7849c69b534c79dcbb3e680a7426f';
        $result = $this->getHashingResult(HashAlgo::HAVAL160_5, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval192d5Hash(): void
    {
        $expectedResult = '8e0f51933f9f1bc3735808dfa97703f7e342972b47beabc4';
        $result = $this->getHashingResult(HashAlgo::HAVAL192_5, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval224d5Hash(): void
    {
        $expectedResult = '6bb97c634b8572ff68477541cc2368654ad98cd92663041427fc5608';
        $result = $this->getHashingResult(HashAlgo::HAVAL224_5, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
    public function testCanGenerateHaval256d5Hash(): void
    {
        $expectedResult = '2b52216a7a3cef92e3afff7928eb2e3a92cb0663cc3f1d47f4165c670c590089';
        $result = $this->getHashingResult(HashAlgo::HAVAL256_5, $this->testData1);

        $this->assertSame($expectedResult, $result);
    }
}