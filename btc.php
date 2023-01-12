<?php
require_once './vendor/autoload.php';

use BitWasp\Bitcoin\Address\PayToPubKeyHashAddress;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39Mnemonic;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;

 //生成助记词
function createMnemonicWord(){
    // Bip39
    //$math = Bitcoin::getMath();
    //$network = Bitcoin::getNetwork();
    $random = new Random();
    // 生成随机数(initial entropy)
    $entropy = $random->bytes(Bip39Mnemonic::MIN_ENTROPY_BYTE_LEN);
    $bip39 = MnemonicFactory::bip39();
    // 通过随机数生成助记词
    $mnemonic = $bip39->entropyToMnemonic($entropy);
    // 输出助记词
    return $mnemonic;
}

function createBtcAddress($mnemonicWord,$offset){
    $seedGenerator = new Bip39SeedGenerator();
    // 通过助记词生成种子，传入可选加密串'hello'
    $seed = $seedGenerator->getSeed($mnemonicWord);
    echo "seed: " . $seed->getHex() . PHP_EOL;				//种子
    $hdFactory = new HierarchicalKeyFactory();
    $master = $hdFactory->fromEntropy($seed);
    $hardened = $master->derivePath("44/0'/0'/0/".$offset);    //44的含义：https://github.com/bitcoin/bips
    echo 'WIF: ' . $hardened->getPrivateKey()->toWif();		  //私钥
    $address = new PayToPubKeyHashAddress($hardened->getPublicKey()->getPubKeyHash());
    return $address->getAddress();
}

$addr = createBtcAddress(createMnemonicWord(), 0);
var_dump($addr);