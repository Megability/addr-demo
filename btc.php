<?php
require_once './vendor/autoload.php';

use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39Mnemonic;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Address\AddressCreator;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Script\P2shScript;
use BitWasp\Bitcoin\Script\ScriptFactory;

//https://github.com/andkom/php-bitcoin-address
use AndKom\Bitcoin\Address\Output\OutputFactory;
use AndKom\Bitcoin\Address\Taproot;

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
    echo "mnemonic: " . $mnemonic . PHP_EOL;
    return $mnemonic;
}

function createBtcAddress($mnemonicWord){
    $seedGenerator = new Bip39SeedGenerator();
    // 通过助记词生成种子，传入可选加密串'hello'
    $seed = $seedGenerator->getSeed($mnemonicWord);
    echo "seed: " . $seed->getHex() . PHP_EOL;				//种子
    //$hdFactory = new HierarchicalKeyFactory();
    //$master = $hdFactory->fromEntropy($seed);
    //$hardened = $master->derivePath("44'/0'/0'/0/".$offset);    //44的含义：https://github.com/bitcoin/bips
    //echo 'WIF: ' . $hardened->getPrivateKey()->toWif() . PHP_EOL;		  //私钥
    
    $pss = [44,49,84,86];//BIP44/49/84/86：规定 4 种标准的推导路径，地址分别是 1 、3 、bc1q 、bc1p 开头，脚本类型是 P2PKH 、P2SH-P2WPKH 、P2WPKH 、P2TR
    foreach($pss as $p){
        purpose($seed, $p);
    }
}

function getScriptPubKey(HierarchicalKey $key, $purpose)
{
    switch ($purpose) {
        case 44:
            $address = OutputFactory::p2pkh(hex2bin($key->getPublicKey()->getPubKeyHash()->getHex()))->address();
            var_dump($address);

            return ScriptFactory::scriptPubKey()->p2pkh($key->getPublicKey()->getPubKeyHash());
        case 49:
            $factory = new OutputFactory();
            $p2wpkh = $factory->p2wpkh(hex2bin($key->getPublicKey()->getPubKeyHash()->getHex()));
            $address = $factory->p2sh($p2wpkh)->address();
            var_dump($address);

            $rs = new P2shScript(ScriptFactory::scriptPubKey()->p2wkh($key->getPublicKey()->getPubKeyHash()));
            return $rs->getOutputScript();
        case 84:
            $address = OutputFactory::p2wpkh(hex2bin($key->getPublicKey()->getPubKeyHash()->getHex()))->address();
            var_dump($address);

            return ScriptFactory::scriptPubKey()->p2wkh($key->getPublicKey()->getPubKeyHash());
        case 86:
            $taprootPubKey = Taproot::construct(hex2bin($key->getPublicKey()->getHex()));
            $address = OutputFactory::p2tr($taprootPubKey)->address();
            var_dump($address);
            return ;
        default:
            throw new \InvalidArgumentException("Invalid purpose");
    }
}

function purpose($seed, $purpose){
    $factory = new HierarchicalKeyFactory();
    $root = $factory->fromEntropy($seed);
    //echo "Root key (m): " . $root->toExtendedKey() . PHP_EOL;
    //echo "Root key (M): " . $root->toExtendedPublicKey() . PHP_EOL;

    //echo "\n\n -------------- \n\n";

    //echo "Derive (m -> m/{$purpose}'/0'/0'): \n";
    $purposePriv = $root->derivePath("{$purpose}'/0'/0'");
    //echo "m/{$purpose}'/0'/0': ".$purposePriv->toExtendedPrivateKey().PHP_EOL;
    //echo "M/{$purpose}'/0'/0': ".$purposePriv->toExtendedPublicKey().PHP_EOL;
    /*
    echo "Derive (M -> m/{$purpose}'/0'/0'): .... should fail\n";

    try {
        $rootPub = $root->withoutPrivateKey();
        $rootPub->derivePath("{$purpose}'/0'/0'");
    } catch (\Exception $e) {
        echo "caught exception, yes this is impossible: " . $e->getMessage().PHP_EOL;
    }
    */

    $purposePub = $purposePriv->toExtendedPublicKey();

    //echo "\n\n -------------- \n\n";

    echo "initialize from xpub (M/{$purpose}'/0'/0'): \n";

    $xpub = $factory->fromExtended($purposePub);

    $addressCreator = new AddressCreator();

    $script0 = getScriptPubKey($xpub->derivePath("0/0"), $purpose);
    if($purpose<86){
        echo "0/0: ".$addressCreator->fromOutputScript($script0)->getAddress().PHP_EOL;
    }
    echo "0/0-PrivateKey: ".$root->derivePath("{$purpose}'/0'/0'/0/0")->getPrivateKey()->toWif().PHP_EOL;
    

    //$script1 = getScriptPubKey($xpub->derivePath("0/1"), $purpose);
    //if($purpose<86){
    //    echo "0/1: ".$addressCreator->fromOutputScript($script1)->getAddress().PHP_EOL;
    //}
    //echo "0/1-PrivateKey: ".$root->derivePath("{$purpose}'/0'/0'/0/1")->getPrivateKey()->toWif().PHP_EOL;
}

$addr = createBtcAddress(createMnemonicWord());
