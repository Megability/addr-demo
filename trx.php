<?php
require_once './vendor/autoload.php';

use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;


use Elliptic\EC;
use IEXBase\TronAPI\Support\Base58;
use IEXBase\TronAPI\Support\Crypto;
use IEXBase\TronAPI\Support\Hash;
use IEXBase\TronAPI\Support\Keccak;


$mnemonic = "scheme spot photo card baby mountain device kick cradle pact join borrow";
$seedGenerator = new Bip39SeedGenerator();
// 通过助记词生成种子，传入可选加密串'hello'
$seed = $seedGenerator->getSeed($mnemonic);
$hdFactory = new HierarchicalKeyFactory();
$master = $hdFactory->fromEntropy($seed);
$hardened = $master->derivePath("44'/195'/0'/0/0");
$pri = $hardened->getPrivateKey()->getHex();
$pubKeyHex = $hardened->getPublicKey()->getHex();
privateKeyToAddress($pri);

function privateKeyToAddress($privateKey)
{
    $ec = new EC('secp256k1');

    // Generate keys
    //$key = $ec->genKeyPair();
    $priv = $ec->keyFromPrivate($privateKey);
    $pubKeyHex = $priv->getPublic(false, "hex");

    $pubKeyBin = hex2bin($pubKeyHex);
    $addressHex = getAddressHex($pubKeyBin);
    $addressBin = hex2bin($addressHex);
    $addressBase58 = getBase58CheckAddress($addressBin);
    $addr = [
        'private_key' => $priv->getPrivate('hex'),
        'public_key'    => $pubKeyHex,
        'address_hex' => $addressHex,
        'address_base58' => $addressBase58
    ];
    print_r($addr);
}

function getAddressHex(string $pubKeyBin): string
{
    if (strlen($pubKeyBin) == 65) {
        $pubKeyBin = substr($pubKeyBin, 1);
    }

    $hash = Keccak::hash($pubKeyBin, 256);

    return '41' . substr($hash, 24);
}
function getBase58CheckAddress(string $addressBin): string
{
    $hash0 = Hash::SHA256($addressBin);
    $hash1 = Hash::SHA256($hash0);
    $checksum = substr($hash1, 0, 4);
    $checksum = $addressBin . $checksum;

    return Base58::encode(Crypto::bin2bc($checksum));
}