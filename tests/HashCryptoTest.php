<?php

use Furbyus\Hashing\Hash;
use Furbyus\Hashing\Enum\HashAlgo;

final class HashCryptoTest extends \PHPUnit\Framework\TestCase
{
    private string $testData1 = "String to hash test";
    private string $testData2 = "Another string to test";
    private string $key1 = "secrets";
    private string $key2 = "AnotherSecret";

    private function compareHash(string $knownHash, string $algorithm, ?string $data = null, ?string $key = null): bool
    {
        $data = $data ? $data : $this->testData1;
        $key = $key ? $key : $this->key1;
        return Hash::compare($knownHash, $data, $algorithm, $key);
    }

    private function comparePossibleCombinations(string $algorithm, string $knownHash): void
    {
        /* Same data & key */
        $result = $this->compareHash($knownHash, $algorithm);
        $this->assertSame(true, $result);

        /* Different data & same key */
        $result = $this->compareHash($knownHash, $algorithm, $this->testData2);
        $this->assertSame(false, $result);

        /* Different data & different key */
        $result = $this->compareHash($knownHash, $algorithm, $this->testData2, $this->key2);
        $this->assertSame(false, $result);

        /* Same data & different key */
        $result = $this->compareHash($knownHash, $algorithm, $this->testData1, $this->key2);
        $this->assertSame(false, $result);
    }

    public function testCannotGenerateCryptographicHashWithNonCryptographicAlgorithmCrc32(): void
    {
        $this->expectException(\LogicException::class);
        Hash::make($this->testData1, HashAlgo::CRC32, $this->key1);
    }
    public function testCannotGenerateCryptographicHashWithNonCryptographicAlgorithmAdler32(): void
    {
        $this->expectException(\LogicException::class);
        Hash::make($this->testData1, HashAlgo::ADLER32, $this->key1);
    }
    public function testCannotGenerateCryptographicHashWithNonCryptographicAlgorithmJoaat(): void
    {
        $this->expectException(\LogicException::class);
        Hash::make($this->testData1, HashAlgo::JOAAT, $this->key1);
    }
    public function testCannotGenerateCryptographicHashWithNonCryptographicAlgorithmFnv132(): void
    {
        $this->expectException(\LogicException::class);
        Hash::make($this->testData1, HashAlgo::FNV132, $this->key1);
    }
    public function testCannotGenerateCryptographicHashWithNonCryptographicAlgorithmMurmur3A(): void
    {
        $this->expectException(\LogicException::class);
        Hash::make($this->testData1, HashAlgo::MURMUR3A, $this->key1);
    }
    public function testCanGenerateAndCompareCryptographicMd2Hash(): void
    {
        $knownHash = '1e31af0624a263d7b85508520dd56100';
        $this->comparePossibleCombinations(HashAlgo::MD2, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicMd4Hash(): void
    {
        $knownHash = 'f101abe6b49a95dc85872f7493d39b1b';
        $this->comparePossibleCombinations(HashAlgo::MD4, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicMd5Hash(): void
    {
        $knownHash = '7b1dea50415e7d6cfcbc92c2f46d5bd8';
        $this->comparePossibleCombinations(HashAlgo::MD5, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha1Hash(): void
    {
        $knownHash = '15383c4b66c3421ee3b35248c0ff8f8f4a4dcf89';
        $this->comparePossibleCombinations(HashAlgo::SHA1, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha224Hash(): void
    {

        $knownHash = '9bf5d2a429d8874c56b8becfaabae8b155f45641b889649967e4213a';
        $this->comparePossibleCombinations(HashAlgo::SHA224, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha256Hash(): void
    {
        $knownHash = '50f91f58519c7530b75c47ea3c8352b50587af361b41e4adb80252f4d55d978c';
        $this->comparePossibleCombinations(HashAlgo::SHA256, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha384Hash(): void
    {
        $knownHash = '672bb62bc8f94098b83e8ba019457815e80ae9350d4de1e78e6b75b0e3fc6ecefa0b49c20867d2da214eaa87914b1a60';
        $this->comparePossibleCombinations(HashAlgo::SHA384, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha512Hash(): void
    {
        $knownHash = '6c8246d3b6cc2cccb216e5770a9f753fd3028b2d004507130e22dcfde6d2996687f06de6ca79eef532d32ec6418f6c11e5f1dbb0e62d17d1e34120becf43a3ba';
        $this->comparePossibleCombinations(HashAlgo::SHA512, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha512d224Hash(): void
    {
        $knownHash = '4eb9eb93a07b8f9091eca5894056a320a8169cc09da3c2821519c812';
        $this->comparePossibleCombinations(HashAlgo::SHA512_224, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha512d256Hash(): void
    {
        $knownHash = 'dbca480d43621a82bfdb6059081a88ab6b77010ceb37a73fb1e630fff7cb69ae';
        $this->comparePossibleCombinations(HashAlgo::SHA512_256, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha3d224Hash(): void
    {
        $knownHash = '82baf99fa8db2432ff960e633bb5f78863186cfe299c9c158affe3bf';
        $this->comparePossibleCombinations(HashAlgo::SHA3_224, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha3d256Hash(): void
    {
        $knownHash = '298db22b16565bdae3ea17541299c3a946e5aabc19f14826734de6050eb2ad54';
        $this->comparePossibleCombinations(HashAlgo::SHA3_256, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha3d384Hash(): void
    {
        $knownHash = '4b2b3d0e3bdc64bab80b2c7b7cd1a5dce6f2c342f553e9ee7503eb5030d7db4fe2d778cc8ed12dac6d7ab78fcf35b9f6';
        $this->comparePossibleCombinations(HashAlgo::SHA3_384, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicSha3d512Hash(): void
    {
        $knownHash = '65a32cbe54295af94c82684b9e82e2cedc80a85bae9d91ba50a67bc431c548cc4e55055bd44decdcfd09aea36c4f5f40fec949f8be380fbbae6f56bf73eab5d8';
        $this->comparePossibleCombinations(HashAlgo::SHA3_512, $knownHash);
    }

    public function testCanGenerateAndCompareCryptographicRipemd128Hash(): void
    {
        $knownHash = 'bc2a23f8d387ea4d9aada69a54941c7f';
        $this->comparePossibleCombinations(HashAlgo::RIPEMD128, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicRipemd160Hash(): void
    {
        $knownHash = '7cd7121493464a86a56f63ee7d1367ad939a190e';
        $this->comparePossibleCombinations(HashAlgo::RIPEMD160, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicRipemd256Hash(): void
    {
        $knownHash = '3c8cf1ce620fed12fd3b0100ae3670acd59c211d9ba8988ae079fbc4899cf1f5';
        $this->comparePossibleCombinations(HashAlgo::RIPEMD256, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicRipemd320Hash(): void
    {
        $knownHash = 'e264b109f80e77f29cc8555c4d3c1f9fa18bd7932b9e196ff06606afea3dda5abc7645d91a057c6e';
        $this->comparePossibleCombinations(HashAlgo::RIPEMD320, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicWhirlpoolHash(): void
    {
        $knownHash = '3e253b9e893968b46d6c8ed09ae2a761d27d49dffde0020d0d8faa4ab0e68b8a79691884b5d69dc560ad39c9359762cb6a9befb3f59d741d1da10ce3f97fd13e';
        $this->comparePossibleCombinations(HashAlgo::WHIRLPOOL, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicTiger128d3Hash(): void
    {
        $knownHash = 'bb00558b1c6cc08701c77f1b914b6c6b';
        $this->comparePossibleCombinations(HashAlgo::TIGER128_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicTiger160d3Hash(): void
    {
        $knownHash = 'cdf38fc06d944f0a86f6fa2c9324d099dc727a72';
        $this->comparePossibleCombinations(HashAlgo::TIGER160_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicTiger192d3Hash(): void
    {
        $knownHash = '036fd241fd9cb372d2f90b8fe5c8ce7f0f4246483a0aeec8';
        $this->comparePossibleCombinations(HashAlgo::TIGER192_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicTiger128d4Hash(): void
    {
        $knownHash = 'e4d35e616b695e7289ca9d5780add7ce';
        $this->comparePossibleCombinations(HashAlgo::TIGER128_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicTiger160d4Hash(): void
    {
        $knownHash = '43ef213fce4f485a5407f9e0a390e2ecbfb55ccb';
        $this->comparePossibleCombinations(HashAlgo::TIGER160_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicTiger192d4Hash(): void
    {
        $knownHash = '050753145e1bc5d207c98c7dc5ddcd9ef09e51e698812aad';
        $this->comparePossibleCombinations(HashAlgo::TIGER192_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicSnefruHash(): void
    {
        $knownHash = '6f440f8ea5231b8143ddc214d67abc20cd6b36c3fbd4debbff324d1a4e541804';
        $this->comparePossibleCombinations(HashAlgo::SNEFRU, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicSnefru256Hash(): void
    {
        $knownHash = '6f440f8ea5231b8143ddc214d67abc20cd6b36c3fbd4debbff324d1a4e541804';
        $this->comparePossibleCombinations(HashAlgo::SNEFRU256, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicGostHash(): void
    {
        $knownHash = '99113427396ddcecb8560cc5d3a477b15d06996e3e2425c80170041c2f8e46fe';
        $this->comparePossibleCombinations(HashAlgo::GOST, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicGostCryptoHash(): void
    {
        $knownHash = 'b6652d1e5d4062d17dc0d85810579f8687d0feaac0d8cb2a7bd89c6deaa12b7e';
        $this->comparePossibleCombinations(HashAlgo::GOST_CRYPTO, $knownHash);

    }


    public function testCanGenerateAndCompareCryptographicHaval128d3Hash(): void
    {
        $knownHash = '720bf10606ec52d21f43370f40767708';
        $this->comparePossibleCombinations(HashAlgo::HAVAL128_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval160d3Hash(): void
    {
        $knownHash = '60aa3c697b51f59bde818b1f7845d0c16841c974';
        $this->comparePossibleCombinations(HashAlgo::HAVAL160_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval192d3Hash(): void
    {
        $knownHash = '7ee0781d01a441936d8f23736503e294fcb0aaee336be569';
        $this->comparePossibleCombinations(HashAlgo::HAVAL192_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval224d3Hash(): void
    {
        $knownHash = 'fdf8e54f145257c0926375e88baad7da92a897815ef558f19fdb532e';
        $this->comparePossibleCombinations(HashAlgo::HAVAL224_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval256d3Hash(): void
    {
        $knownHash = '18303b963302ebaba5501b25215105e247c79afe314e34668612d0d5bf3a3ce3';
        $this->comparePossibleCombinations(HashAlgo::HAVAL256_3, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval128d4Hash(): void
    {
        $knownHash = '071c4568726ba06cfe05c60c22efa1b7';
        $this->comparePossibleCombinations(HashAlgo::HAVAL128_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval160d4Hash(): void
    {
        $knownHash = 'c05d6c6002b86738f98ced5a50435728e783444b';
        $this->comparePossibleCombinations(HashAlgo::HAVAL160_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval192d4Hash(): void
    {
        $knownHash = 'ee94ceb4043cbe63cfd167701b505b8b5b3dcaabc95ee639';
        $this->comparePossibleCombinations(HashAlgo::HAVAL192_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval224d4Hash(): void
    {
        $knownHash = 'a8e519ab285650f2cfe8533e4a1ec9edb531434da9956aff872a730b';
        $this->comparePossibleCombinations(HashAlgo::HAVAL224_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval256d4Hash(): void
    {
        $knownHash = '30804e2b8ab095dd33c346bedf9e3b22b58be086576f3d76ce15948bb6a42f32';
        $this->comparePossibleCombinations(HashAlgo::HAVAL256_4, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval128d5Hash(): void
    {
        $knownHash = 'f244e5d37fdbabb0a43e1610f70420d0';
        $this->comparePossibleCombinations(HashAlgo::HAVAL128_5, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval160d5Hash(): void
    {
        $knownHash = '73e939de40773b1dea9a4b95f924b5eb008bc03b';
        $this->comparePossibleCombinations(HashAlgo::HAVAL160_5, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval192d5Hash(): void
    {
        $knownHash = '673e2b647f465b9bb0b164d3e8c566f24fc260ab5838933e';
        $this->comparePossibleCombinations(HashAlgo::HAVAL192_5, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval224d5Hash(): void
    {
        $knownHash = '8d0348a7acb07e68323db1ad78a63a97b9bdb27767c0e40752dc0627';
        $this->comparePossibleCombinations(HashAlgo::HAVAL224_5, $knownHash);

    }

    public function testCanGenerateAndCompareCryptographicHaval256d5Hash(): void
    {
        $knownHash = '49ceb29671580c0a4492fe6521909130a3cc116c8976df8939fbcc7f23ba511f';
        $this->comparePossibleCombinations(HashAlgo::HAVAL256_5, $knownHash);

    }
}