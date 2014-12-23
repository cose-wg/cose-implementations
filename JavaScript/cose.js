/*
 * Copyright (c) 2014 James Schaad <ietf@augustcellars.com>
 */


var EncryptMessage = function(content) {

    if ((content == null) || (content == undefined)) {
        //  Do nothing
    }
    else if ((typeof content == "string") || (content instanceof String)) {
        this.SetContent(content);
    }
    else if ((content instanceof Int8Array) || (content instanceof Uint8Array)) {
        plainText = content;
    }
    else throw "Incorrect content type";

    this.objProtected  =  {};
    this.objUnprotected  =  {};
    this.iv =  null;
    this.aad =  null;
    this.cipherText =  null;
    this.recipientList =  [];
    this.cek =  null;


}

//
EncryptMessage.prototype = {
//    objProtected : {},
//    objUnprotected : {},
//    iv: null,
//    aad: null,
//    cipherText: null,
//    plainText: null,
//    recipientList: [],
//    cek: null,

    AddProtected: function(key, value) {
        if (this.objProtected == null) this.objProtected = {};
        this.objProtected[key] = value;
        if (key in this.objUnprotected) delete this.objUnprotected[key];
    },

    AddUnprotected: function(key, value) {
        if (this.objUnprotected == null) this.objUnprotected = {};
        this.objUnprotected[key] = value;
        if (key in this.objProtected) delete this.objProtected[key];
    },

    AddRecipient: function(recip) {
        this.recipientList.push(recip);
    },

    DecodeFromCBOR: function(cborValue) { // method that turns a CBOR object into something usable here
        if (cborValue.length < 6) throw "Invalid CBOR object"

        //  Protected values
        if (cborValue[0] == null) this.objProtected = {};
        else this.objProtected = CBOR.decode(cborValue[0]);

        if (cborValue[1] == null) this.objUnprotected = {};
        else this.objUnprotected = cborValue[1];

        this.iv = cborValue[2];

        this.aad = cborValue[3];

        this.cipherText = cborValue[4];

        if (cborValue.length == 6) {
            if (cborValue[5] == null) {
            }
            else {
                this.recipientList = cborValue[5].map(function(r) {
                    var recip = new Recipient();
                    recip.DecodeFromCBOR(r);
                    return recip;
                });
            }
        }
        else {
            var recip = new Recipient();
            recip.DecodeFromCBOR(cborValue.slice(5));
            this.recipientList.push(recip);
        }
    },

    Decrypt: function(key) {
        //  Try and decode the recipients

        var alg = this.FindAttribute("alg");
        var cbitKey = 0;
        var cekAlgorithm;
        var cekAlgImport;
        
        switch (alg) {
            case "A128GCM": cbitKey = 128; break;
            case "A192GCM": cbitKey = 192; break;
            case "A256GCM": cbitKey = 256; break;
            default:
            throw "Unknown content encryption algorithm";
        }

        switch (alg) {
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
            cekAlgorithm = {
                "name": "AES-GCM",
                "iv": this.iv
            };
            cekAlgImport = { "name" : "AES-GCM" };
            break;
        }
            

        var promises = this.recipientList.map(function(r) {
            return r.Decrypt(key, cbitKey, cekAlgImport);
        });
        
        var that = this;
        return Promise.all(promises).then(
            function (cekKey) {
                console.log("cekKey");
                console.log(cekKey);
                return window.crypto.subtle.decrypt(cekAlgorithm, cekKey[0], that.cipherText);
            }
        ).then(function(value) {
            that.plainText = value;
            return value; 
        });
    },

    EncodeToBytes: function() {
        var promise = this.EncodeToCBOR();
        return promise.then(
            function(val) {
                return CBOR.encode(val); } );
    },

    EncodeToCBOR: function() { //  method that turns the structure into CBOR
        var that = this;

        function _fillArray() {
            var cborValue = [];

            if (Object.keys(this.objProtected).length == 0) cborValue[0] = null;
            else cborValue[0] = CBOR.encode(this.objProtected);

            if (Object.keys(this.objUnprotected).length > 0) cborValue[1] = this.objUnprotected;
            else cborValue[1] = null;                            

            cborValue[2] = this.iv;

            cborValue[3] = this.aad;

            cborValue[4] = this.cipherText;

            if (this.recipientList.length == 1) {
                var r = _fillArray.call(this.recipientList[0]);
                cborValue.push.apply(cborValue, r);
            }
            else if (this.recipientList.length == 0) {
                cborValue[5] = null;
            }
            else {
                cborValue[5] = this.recipientList.map(function(r){ return fillArray.call(r); });
            }

            return cborValue;
            
        }

        var promiseEncrypt = null;

        if (this.cipherText == null) promiseEncrypt = this.Encrypt();
        else {
            promiseEncrypt = new Promise(function(myResolve, MyReject){ myResolve(true); });
        }
        

        return promiseEncrypt.then(function() { return _fillArray.call(that);});
    },

    Encrypt: function() {
        var alg = this.FindAttribute("alg");
        var promise;

        if (alg == null) {
            alg = "A128GCM";
            this.AddProtected("alg", alg);
        }

        //  If we are doing direct or ECDH direct, then get a key now

        switch (alg) {
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
            promise = this.AES_Encrypt(alg);
            break;

            default:
            throw "Unrecognized algorithm";
        }

        var that = this;
        var promiseRet = new Promise(function(myResolve, myReject) {

            promise.then( function(aCEK) {
                if (that.recipientList.length == 0) { myResolve(true); return; }

                var recips = that.recipientList.map(function(r){ return r.Encrypt(that.cek); });

                Promise.all(recips).then(function(recipVals) {
                    myResolve(true);
                }, function(val) { myReject(val); });
            }, function(val) { myReject(val); });
        });

        return promiseRet;                            
    },

    FindAttribute : function(key) {
        if ((this.objProtected != null) && (key in this.objProtected)) return this.objProtected[key];
        if ((this.objUnprotected != null) && (key in this.objUnprotected)) return this.objUnprotected[key];
        return null;
    },
    SetContent: function(content) {
        if ((typeof content == "string") || (content instanceof String)) {
            this.plainText = Utf8.str2ab(Utf8.encode(content));
        }
        else if ((content instanceof Int8Array) || (content instanceof Uint8Array)) {
            this.plainText = content;
        }
        else throw "Bad content type";
    },

    AES_Encrypt: function(algorithm) {
        var aesAlgorithmKeyGen = {
            name: "AES-GCM",
            // AesKeyGenParams
            length: 128
        };

        var aesAlgorithmEncrypt = {
            name: "AES-GCM",
            // AesCbcParams
            iv: window.crypto.getRandomValues(new Uint8Array(16))
        };

        var that = this;

        // Create a key generator to produce a one-time-use AES key to encrypt some data
        return window.crypto.subtle.generateKey(aesAlgorithmKeyGen, true, ["encrypt"]).then(
            function(aesKey) {
                that.cek = aesKey;
                return window.crypto.subtle.encrypt(aesAlgorithmEncrypt, aesKey, that.plainText );
            }
        ).then(function(value) {
            that.cipherText = value; 
            that.iv = aesAlgorithmEncrypt["iv"];
            return value;
        });
    }
}

var Recipient = function(key, algorithm) {
    EncryptMessage.call(this);
    this.key = key;
    if (typeof algorithm == "string") this.AddUnprotected("alg", algorithm);
}

Recipient.prototype = Object.create(EncryptMessage.prototype);

Recipient.prototype.Decrypt = function(key, cbitKey, cekAlgorithm) {
    var that = this;
    var kekAlg = this.FindAttribute("alg");
    var importAlgorithm;
    var wrapAlgorithm;

    switch (kekAlg) {
    case "RSA-OAEP-256":
        importAlgorithm = {"name":"RSA-OAEP", "hash":{ "name":"SHA-256"}};
        wrapAlgorithm = {"name":"RSA-OAEP"};
        break;

    default:
        throw "Unrecognized algorithm";
    }

    return window.crypto.subtle.importKey("jwk", key, importAlgorithm, false, ["decrypt", "unwrapKey"]).then (
        function(kekKey) {
            return window.crypto.subtle.unwrapKey("raw", that.cipherText, kekKey, wrapAlgorithm, cekAlgorithm, false, ["decrypt"]);
        }
    );
}

Recipient.prototype.Encrypt = function(cek) {
    var that = this;

    var alg = this.FindAttribute("alg");
    var importAlgorithm;
    var wrapAlgorithm;

    switch (alg) {
    case "RSA-OAEP-256":
        importAlgorithm = { "name":"RSA-OAEP", "hash":{ "name":"SHA-256"}};
        wrapAlgorithm = {"name":"RSA-OAEP"};
        break;

    default:
        throw "Unrecognized algorithm";
    }

    return new Promise(
        function(myResolve, myReject)
        {
            window.crypto.subtle.importKey("jwk", that.key, importAlgorithm, false, ["encrypt", "wrapKey"]).then(
                function(kekKey) {
                    return window.crypto.subtle.wrapKey("raw", cek, kekKey, wrapAlgorithm);
                }
            ).then(
                function(val) { 
                    that.cipherText = val;
                    myResolve(val);
                    return val;
                },
                function(val) { 
                    myReject(val);
                    return val;
                }
            )
        }
    );
}
