<?php

namespace Furbyus\Hashing;

use Furbyus\Hashing\CustomAlgo\Crc32ts;
use Furbyus\Hashing\Enum\HashAlgo;

class Hash
{
    public function __construct(
        private string  $algorithm,
        private string  $data,
        private ?string $sum = null,
        private string  $key = "",
        private bool    $cryptographic = false,
        private array   $customHashAlgorithms = [
            HashAlgo::CRC32TS => Crc32ts::class,
        ],
        private array   $customCryptographicHashAlgorithms = [
        ])
    {

    }

    public static function make(string $data, string $algorithm, string $key = ""): string
    {
        $selfInstance = (new self($algorithm, $data))->setCryptographicKey($key);
        return $selfInstance->getHash();
    }

    public static function compare(string $knownHashOrSignature, string $data, string $algorithm, string $key = ""): bool
    {
        $selfInstance = (new self($algorithm, $data))->setCryptographicKey($key);
        return $selfInstance->getComparisonResult($knownHashOrSignature);
    }


    private function setCryptographicKey(string $key): self
    {
        $this->cryptographic = ($key !== "");
        $this->key = $key;
        return $this;
    }

    public function getHash(): string
    {
        return $this->calculateSum()->sum;
    }

    public function getComparisonResult(string $knownHashOrAlgo): bool
    {
        return $this->calculateSum()->compareSum($knownHashOrAlgo);
    }

    private function calculateSum(): self
    {
        if (!isset($this->algorithm)) {
            throw new \LogicException("No Data specified");
        }

        if ($this->cryptographic) {
            if (in_array($this->algorithm, (hash_hmac_algos()))) {
                $this->sum = hash_hmac($this->algorithm, $this->data, $this->key);
            } elseif (array_key_exists($this->algorithm, $this->customCryptographicHashAlgorithms)) {
                $this->sum = (new $this->customCryptographicHashAlgorithms[$this->algorithm]($this->data, $this->key))->getHash();
            } else {
                throw new \LogicException("Algorithm '{$this->algorithm}' is not a valid cryptographic hash algo");
            }
        } else {
            if (in_array($this->algorithm, (hash_algos()))) {
                $this->sum = hash($this->algorithm, $this->data);
            } elseif (array_key_exists($this->algorithm, $this->customHashAlgorithms)) {
                /** @var  $customAlgoClassInstance */
                $customAlgoClassInstance = new $this->customHashAlgorithms[$this->algorithm]($this->data);
                $this->sum = $customAlgoClassInstance->getHash();
            } else {
                throw new \LogicException("Algorithm '{$this->algorithm}' is not a valid hash algo");
            }
        }
        return $this;
    }

    private
    function compareSum(string $knownHashOrSignature): bool
    {
        return hash_equals($this->sum, $knownHashOrSignature);
    }


}