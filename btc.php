<?php
require_once './vendor/autoload.php';

use BitWasp\Bitcoin\Address\PayToPubKeyHashAddress;
use BitWasp\Bitcoin\Address\SegwitAddress;
use BitWasp\Bitcoin\Address\ScriptHashAddress;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39Mnemonic;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Script\WitnessProgram;

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
    echo 'WIF: ' . $hardened->getPrivateKey()->toWif() . PHP_EOL;		  //私钥
    $address = new PayToPubKeyHashAddress($hardened->getPublicKey()->getPubKeyHash());
    echo " * p2pkh address: {$address->getAddress()}" . PHP_EOL;

    $p2wpkhWP = WitnessProgram::v0($hardened->getPublicKey()->getPubKeyHash());
    $p2wpkh = new SegwitAddress($p2wpkhWP);
    $address = $p2wpkh->getAddress();
    echo " * v0 key hash address: {$address}" . PHP_EOL;

    $p2shP2wsh = new ScriptHashAddress(WitnessProgram::v0($hardened->getPublicKey()->getPubKeyHash())->getScript()->getScriptHash());
    echo " * p2sh|p2wsh: {$p2shP2wsh->getAddress()}\n";

}

$addr = createBtcAddress(createMnemonicWord(), 0);
