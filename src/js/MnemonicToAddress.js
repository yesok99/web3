var Mnemonic = function(language) {

    var DOM = {};
    //DOM.entropyContainer = $(".entropy-container");
    //PBKDF2_ROUNDS = DOM.entropyContainer.find(".pbkdf2-rounds").val();
    var RADIX = 2048;

    var self = this;

    var wordlist = WORDLISTS["english"];

    var hmacSHA512 = function(key) {
        var hasher = new sjcl.misc.hmac(key, sjcl.hash.sha512);
        this.encrypt = function() {
            return hasher.encrypt.apply(hasher, arguments);
        };
    };

    function byteArrayToWordArray(data) {
            var a = [];
            for (var i=0; i<data.length/4; i++) {
                v = 0;
                v += data[i*4 + 0] << 8 * 3;
                v += data[i*4 + 1] << 8 * 2;
                v += data[i*4 + 2] << 8 * 1;
                v += data[i*4 + 3] << 8 * 0;
                a.push(v);
            }
            return a;
        }

    function byteArrayToBinaryString(data) {
        var bin = "";
        for (var i=0; i<data.length; i++) {
            bin += zfill(data[i].toString(2), 8);
        }
        return bin;
    }

    function hexStringToBinaryString(hexString) {
        binaryString = "";
        for (var i=0; i<hexString.length; i++) {
            binaryString += zfill(parseInt(hexString[i], 16).toString(2),4);
        }
        return binaryString;
    }

    function binaryStringToWordArray(binary) {
        var aLen = binary.length / 32;
        var a = [];
        for (var i=0; i<aLen; i++) {
            var valueStr = binary.substring(0,32);
            var value = parseInt(valueStr, 2);
            a.push(value);
            binary = binary.slice(32);
        }
        return a;
    }

    function binaryStringToByteArray(binary) {
        var aLen = binary.length / 8;
        var a = [];
        for (var i=0; i<aLen; i++) {
            var valueStr = binary.substring(0,8);
            var value = parseInt(valueStr, 2);
            a.push(value);
            binary = binary.slice(8);
        }
        return a;
    }

    function mnemonicToBinaryString(mnemonic) {
        var mnemonic = self.splitWords(mnemonic);
        if (mnemonic.length == 0 || mnemonic.length % 3 > 0) {
            return null;
        }
        // idx = map(lambda x: bin(self.wordlist.index(x))[2:].zfill(11), mnemonic)
        var idx = [];
        for (var i=0; i<mnemonic.length; i++) {
            var word = mnemonic[i];
            var wordIndex = wordlist.indexOf(word);
            if (wordIndex == -1) {
                return null;
            }
            var binaryIndex = zfill(wordIndex.toString(2), 11);
            idx.push(binaryIndex);
        }
        return idx.join('');
    }

    
    function mnemonicToBinaryString(mnemonic) {
        var mnemonic = self.splitWords(mnemonic);
        if (mnemonic.length == 0 || mnemonic.length % 3 > 0) {
            return null;
        }
        // idx = map(lambda x: bin(self.wordlist.index(x))[2:].zfill(11), mnemonic)
        var idx = [];
        for (var i=0; i<mnemonic.length; i++) {
            var word = mnemonic[i];
            var wordIndex = wordlist.indexOf(word);
            if (wordIndex == -1) {
                return null;
            }
            var binaryIndex = zfill(wordIndex.toString(2), 11);
            idx.push(binaryIndex);
        }
        return idx.join('');
    }

    // Pad a numeric string on the left with zero digits until the given width
    // is reached.
    // Note this differs to the python implementation because it does not
    // handle numbers starting with a sign.
    function zfill(source, length) {
        source = source.toString();
        while (source.length < length) {
            source = '0' + source;
        }
        return source;
    }


    self.entropy = function(byteArray) {

        return byteArrayToBinaryString(byteArray);
        
    }

    
     
    self.toMnemonic = function(byteArray) {
            if (byteArray.length % 4 > 0) {
                throw 'Data length in bits should be divisible by 32, but it is not (' + byteArray.length + ' bytes = ' + byteArray.length*8 + ' bits).'
            }
    
            //h = hashlib.sha256(data).hexdigest()
            //var data = byteArrayToWordArray(byteArray);
            //var hash = sjcl.hash.sha256.hash(data);
            var h = sha256(byteArray);
    
            // b is a binary string, eg '00111010101100...'
            //b = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8) + \
            //    bin(int(h, 16))[2:].zfill(256)[:len(data) * 8 / 32]
            //
            // a = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8)
            // c = bin(int(h, 16))[2:].zfill(256)
            // d = c[:len(data) * 8 / 32]
            var a = byteArrayToBinaryString(byteArray);
            var c = zfill(hexStringToBinaryString(h), 256);
            var d = c.substring(0, byteArray.length * 8 / 32);
            // b = line1 + line2
            var b = a + d;

            var result = [];
            
            var blen = b.length / 11;
            for (var i=0; i<blen; i++) {
                var idx = parseInt(b.substring(i * 11, (i + 1) * 11), 2);
                result.push(wordlist[idx]);
    
            }
            return self.joinWords(result);
    
        };

    self.splitWords = function(mnemonic) {
        return mnemonic.split(/\s/g).filter(function(x) { return x.length; });
    };


    self.joinWords = function(words) {
            // Set space correctly depending on the language
            // see https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md#japanese
            var space = " ";
            if (language == "japanese") {
                space = "\u3000"; // ideographic space
            }
            return words.join(space);
        };

    self.check = function(mnemonic) {
        var b = mnemonicToBinaryString(mnemonic);
        if (b === null) {
            return false;
        }
        var l = b.length;
        //d = b[:l / 33 * 32]
        //h = b[-l / 33:]
        var d = b.substring(0, l / 33 * 32);
        var h = b.substring(l - l / 33, l);
        //nd = binascii.unhexlify(hex(int(d, 2))[2:].rstrip('L').zfill(l / 33 * 8))
        var nd = binaryStringToByteArray(d);
        //nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[:l / 33]
        // var ndHash = sjcl.hash.sha256.hash(nd);
        // var ndHex = sjcl.codec.hex.fromBits(ndHash);
        var ndHex = sha256(nd);
        var ndBstr = zfill(hexStringToBinaryString(ndHex), 256);
        var nh = ndBstr.substring(0,l/33);
        return h == nh;
    }

    self.creatMnemonic = function(numWords) {

        // var numWords = 12;
        //generateRandomPhrase
        
        var strength = numWords / 3 * 32;
        var buffer = new Uint8Array(strength / 8);
        
        var byteArray  = crypto.getRandomValues(buffer);
        
        var words = this.toMnemonic(byteArray);
        
        // console.log(words)
    
        return words;

    }

    self.toSeed = function(mnemonic, passphrase) {

        const PBKDF2_ROUNDS = 2048;
        passphrase = passphrase || '';
        mnemonic = self.joinWords(self.splitWords(mnemonic)); // removes duplicate blanks
        var mnemonicNormalized = self.normalizeString(mnemonic);
        passphrase = self.normalizeString(passphrase)
        passphrase = "mnemonic" + passphrase;
        var mnemonicBits = sjcl.codec.utf8String.toBits(mnemonicNormalized);
        var passphraseBits = sjcl.codec.utf8String.toBits(passphrase);
        var result = sjcl.misc.pbkdf2(mnemonicBits, passphraseBits, PBKDF2_ROUNDS, 512, hmacSHA512);
        var hashHex = sjcl.codec.hex.fromBits(result);
        return hashHex;
    }

    self.splitWords = function(mnemonic) {
        return mnemonic.split(/\s/g).filter(function(x) { return x.length; });
    }

    self.normalizeString = function(str) {
        return str.normalize("NFKD");
    }

}

function calcBip32ExtendedKey(bip32RootKey, path) {
        // Check there's a root key to derive from
        if (!bip32RootKey) {
            return bip32RootKey;
        }
        var extendedKey = bip32RootKey;
        // Derive the key from the path
        var pathBits = path.split("/");
        for (var i=0; i<pathBits.length; i++) {
            var bit = pathBits[i];
            var index = parseInt(bit);
            if (isNaN(index)) {
                continue;
            }
            var hardened = bit[bit.length-1] == "'";
            var isPriv = !(extendedKey.isNeutered());
            var invalidDerivationPath = hardened && !isPriv;
            if (invalidDerivationPath) {
                extendedKey = null;
            }
            else if (hardened) {
                extendedKey = extendedKey.deriveHardened(index);
            }
            else {
                extendedKey = extendedKey.derive(index);
            }
        }
        return extendedKey;
    }




function creatAccount(_Mnemonic='', network=0, numAccount=1) {

    const bitNetwork = 0;
    const EthNetwork = 60;
    var mnemonic = _Mnemonic;
    let n = new Mnemonic('english');

    if(_Mnemonic == '') {

        mnemonic = n.creatMnemonic(12);  
    } 
        
    console.log('助记词: ', mnemonic);
    var seed = n.toSeed(mnemonic,'');
    
    var bip32RootKey = libs.bitcoin.HDNode.fromSeedHex(seed);
    
    // bitcoin network
    var derivationPath = "m/0'/0'/0'/0"; 
    
    if(network == bitNetwork)

        derivationPath = "m/44'/0'/0'/0";
    
    if(network == EthNetwork)
    
        derivationPath = "m/44'/60'/0'/0";
    
    var bip32ExtendedKey = calcBip32ExtendedKey(bip32RootKey, derivationPath);
    
    var keyPair, privKey, pubkey, address;
    var account = [];
    
    for(let i=0; i< numAccount; i++) {

        keyPair = bip32ExtendedKey.derive(i).keyPair;
    
        privKey = keyPair.toWIF();
        
        pubkey = keyPair.getPublicKeyBuffer().toString('hex');
        
        address = keyPair.getAddress().toString();
        
        
        if (network == EthNetwork) {
            var pubkeyBuffer = keyPair.getPublicKeyBuffer();
            var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
            var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
            var hexAddress = addressBuffer.toString('hex');
            var checksumAddress = libs.ethUtil.toChecksumAddress(hexAddress);
            address = libs.ethUtil.addHexPrefix(checksumAddress);
            pubkey = libs.ethUtil.addHexPrefix(pubkey);
            // if (hasPrivkey) {
                privkey = libs.ethUtil.bufferToHex(keyPair.d.toBuffer(32));
            // }
        }

        account.push({

            privKey: privKey,
            pubkey: pubkey,
            address :address
            
        })
        
    }
 
    return account;
    
    
    
    // console.log('bip32RootKey 根密钥: ', bip32RootKey.toBase58());
    // console.log('bip32ExtendedKey 拓展密钥: ', bip32ExtendedKey.toBase58());
    console.log('privKey: ', privKey);
    console.log('pubkey: ', pubkey);
    console.log('address: ', address);

}

// var n = new Mnemonic('english');

// var mnemonic = n.creatMnemonic(12);



