<?php
require_once './vendor/autoload.php';

use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39Mnemonic;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use Web3p\EthereumUtil\Util;	//头部要额外引入这个类

// Bip39
$math = Bitcoin::getMath();
$network = Bitcoin::getNetwork();
$random = new Random();
// 生成随机数(initial entropy)
$entropy = $random->bytes(Bip39Mnemonic::MIN_ENTROPY_BYTE_LEN);
$bip39 = MnemonicFactory::bip39();
// 通过随机数生成助记词
$mnemonic = $bip39->entropyToMnemonic($entropy);
echo "mnemonic: " . $mnemonic.PHP_EOL.PHP_EOL;// 助记词

$seedGenerator = new Bip39SeedGenerator();
// 通过助记词生成种子，传入可选加密串'hello'或其他，默认空字符串
$seed = $seedGenerator->getSeed($mnemonic);
echo "seed: " . $seed->getHex() . PHP_EOL;
$hdFactory = new HierarchicalKeyFactory();
$master = $hdFactory->fromEntropy($seed);

$util = new Util();
// 设置路径account
$hardened = $master->derivePath("44'/60'/0'/0/0");
echo " - m/44'/60'/0'/0/0 " .PHP_EOL;
echo " public key: " . $hardened->getPublicKey()->getHex().PHP_EOL;
echo " private key: " . $hardened->getPrivateKey()->getHex().PHP_EOL;// 可以导入到imtoken使用的私钥
echo " address: " . $util->publicKeyToAddress($util->privateKeyToPublicKey($hardened->getPrivateKey()->getHex())) . PHP_EOL;// 私钥导入imtoken后一样的地址