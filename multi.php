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

use Web3p\EthereumUtil\Util;	//头部要额外引入这个类

use Elliptic\EC;
use IEXBase\TronAPI\Support\Base58;
use IEXBase\TronAPI\Support\Crypto;
use IEXBase\TronAPI\Support\Hash;
use IEXBase\TronAPI\Support\Keccak;

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
    $hardened = $master->derivePath("44'/0'/0'/0/".$offset);    //44的含义：https://github.com/bitcoin/bips
    echo 'WIF: ' . $hardened->getPrivateKey()->toWif() . PHP_EOL;		  //私钥

    $pss = [44,49,84];
    foreach($pss as $p){
        purpose($seed, $p);
    }
}

function createEthAddress($mnemonic){
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
}

function createTrxAddress($mnemonic){
    $seedGenerator = new Bip39SeedGenerator();
    // 通过助记词生成种子，传入可选加密串'hello'
    $seed = $seedGenerator->getSeed($mnemonic);
    $hdFactory = new HierarchicalKeyFactory();
    $master = $hdFactory->fromEntropy($seed);
    $hardened = $master->derivePath("44'/195'/0'/0/0");
    $pri = $hardened->getPrivateKey()->getHex();
    $pubKeyHex = $hardened->getPublicKey()->getHex();
    privateKeyToAddress($pri);
}

//-------------------------------------------------------
function getScriptPubKey(HierarchicalKey $key, $purpose)
{
    switch ($purpose) {
        case 44:
            return ScriptFactory::scriptPubKey()->p2pkh($key->getPublicKey()->getPubKeyHash());
        case 49:
            $rs = new P2shScript(ScriptFactory::scriptPubKey()->p2wkh($key->getPublicKey()->getPubKeyHash()));
            return $rs->getOutputScript();
        case 84:
            return ScriptFactory::scriptPubKey()->p2wkh($key->getPublicKey()->getPubKeyHash());
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
    //$script1 = getScriptPubKey($xpub->derivePath("0/1"), $purpose);
    echo "0/0: ".$addressCreator->fromOutputScript($script0)->getAddress().PHP_EOL;
    //echo "0/1: ".$addressCreator->fromOutputScript($script1)->getAddress().PHP_EOL;
}
//-------------------------------------------------------

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

$mnemonic = createMnemonicWord();
//$mnemonic = 'clerk copy mushroom cruel element tent crane enable tail better gather sting';
echo "========$mnemonic=========" .PHP_EOL;
createBtcAddress($mnemonic, 0);
echo "===============================================" .PHP_EOL;
createEthAddress($mnemonic);
echo "===============================================" .PHP_EOL;
createTrxAddress($mnemonic);