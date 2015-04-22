/*
 * Copyright (c) 2014 James Schaad <ietf@augustcellars.com>
 */
"use strict";

var EncryptMessage = function(content) {

    if ((content === null) || (content == undefined)) {
        //  Do nothing
    }
    else if ((typeof content == "string") || (content instanceof String)) {
        this.SetContent(content);
    }
    else if ((content instanceof Int8Array) || (content instanceof Uint8Array)) {
        this.plainText = content;
    }
    else throw "Incorrect content type";

    this.iv =  null;
    this.aad =  null;
    this.cipherText =  null;
    this.recipientList =  [];
    this.cek =  null;
    this.objProtected = {};
    this.objUnprotected = {};

};

//
EncryptMessage.prototype = {

    AddProtected: function(key, value) {
        this.objProtected[key] = value;
        if (key in this.objUnprotected) delete this.objUnprotected[key];
    },

    AddUnprotected: function(key, value) {
        this.objUnprotected[key] = value;
        if (key in this.objProtected) delete this.objProtected[key];
    },

    AddRecipient: function(recip) {
        this.recipientList.push(recip);
    },

    DecodeFromCBOR: function(cborValue) { // method that turns a CBOR object into something usable here
        if (cborValue.length < 6) throw "Invalid CBOR object";

        //  Protected values
        if (cborValue[0] === null) this.objProtected = {};
        else this.objProtected = CBOR.decode(cborValue[0]);

        if (cborValue[1] === null) this.objUnprotected = {};
        else this.objUnprotected = cborValue[1];

        this.iv = cborValue[2];

        this.aad = cborValue[3];

        this.cipherText = cborValue[4];

        if (cborValue.length == 6) {
            if (cborValue[5] === null) {
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

        default:
            throw "Unknown content encryption algorithm";
        }

        var cborObj = [];
        if (this.objProtected.length === 0) cborObj[0] = null;
        else cborObj[0] = CBOR.encode(this.objProtected);

        if (this.aad === null) cborObj[1] = null;
        else cborObj[1] = this.aad;

        cekAlgorithm["additionalData"] = new Uint8Array(CBOR.encode(cborObj));

        var promises = this.recipientList.map(function(r) {
            return r.Decrypt(key, cbitKey, cekAlgImport);
        });
        
        var that = this;
        return Promise.all(promises).then(
            function (cekKey) {
                var i;
                for (i=0; i<cekKey.length; i++) {
                    if (cekKey[i] instanceof CryptoKey) {
                        return window.crypto.subtle.decrypt(cekAlgorithm, cekKey[i], that.cipherText);
                    }
                }
                return Promise.reject("No key matches");
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

            if (Object.keys(this.objProtected).length === 0) cborValue[0] = null;
            else cborValue[0] = CBOR.encode(this.objProtected);

            if (Object.keys(this.objUnprotected).length > 0) cborValue[1] = this.objUnprotected;
            else cborValue[1] = null;                            

            cborValue[2] = this.iv;

            cborValue[3] = this.aad;

            cborValue[4] = new Uint8Array(this.cipherText);

            if (this.recipientList.length == 1) {
                var r = _fillArray.call(this.recipientList[0]);
                cborValue.push.apply(cborValue, r);
            }
            else if (this.recipientList.length === 0) {
                cborValue[5] = null;
            }
            else {
                cborValue[5] = this.recipientList.map(function(r) { return fillArray.call(r); });
            }

            return cborValue;
            
        }

        var promiseEncrypt = null;

        if (this.cipherText === null) promiseEncrypt = this.Encrypt();
        else {
            promiseEncrypt = new Promise(function(myResolve, MyReject) { myResolve(true); });
        }
        

        return promiseEncrypt.then(function() { return _fillArray.call(that);});
    },

    Encrypt: function() {
        var that = this;

        function AES_Encrypt (algorithm) {
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

            var cborObj = [];
            if (that.objProtected.length === 0) cborObj[0] = null;
            else cborObj[0] = CBOR.encode(that.objProtected);

            if (that.aad === null) cborObj[1] = null;
            else cborObj[1] = that.aad;

            aesAlgorithmEncrypt["additionalData"] = new Uint8Array(CBOR.encode(cborObj));


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

        var alg = this.FindAttribute("alg");
        var promise;

        if (alg === null) {
            alg = "A128GCM";
            this.AddProtected("alg", alg);
        }

        //  If we are doing direct or ECDH direct, then get a key now

        switch (alg) {
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
            promise = AES_Encrypt(alg);
            break;

            default:
            throw "Unrecognized algorithm";
        }

        var promiseRet = new Promise(function(myResolve, myReject) {

            promise.then( function(aCEK) {
                if (that.recipientList.length === 0) { myResolve(true); return; }

                var recips = that.recipientList.map(function(r) { return r.Encrypt(that.cek); });

                Promise.all(recips).then(function(recipVals) {
                    myResolve(true);
                }, function(val) { myReject(val); });
            }, function(val) { myReject(val); });
        });

        return promiseRet;                            
    },

    FindAttribute : function(key) {
        if ((this.objProtected !== null) && (key in this.objProtected)) return this.objProtected[key];
        if ((this.objUnprotected !== null) && (key in this.objUnprotected)) return this.objUnprotected[key];
        return null;
    },

    SetContent: function(content) {
        if ((typeof content == "string") || (content instanceof String)) {
            this.plainText = Utf8.encode(content);
        }
        else if ((content instanceof Int8Array) || (content instanceof Uint8Array)) {
            this.plainText = content;
        }
        else throw "Bad content type";
    }

};

var Recipient = function(key, algorithm) {
    EncryptMessage.call(this);
    this.key = key;
    if (typeof algorithm == "string") this.AddUnprotected("alg", algorithm);
};

Recipient.prototype = Object.create(EncryptMessage.prototype);

Recipient.prototype.Decrypt = function(key, cbitKey, cekAlgorithm) {

    var that = this;
    var kekAlg = this.FindAttribute("alg");
    var importAlgorithm;
    var wrapAlgorithm;
    var importPublicAlgorithm;
    var importPrivateAlgorithm;
    var deriveAlgorithm;


    function keyAgree()
    {
        var kaPrivate;

        return window.crypto.subtle.importKey("jwk", key, importPrivateAlgorithm, false, ["deriveKey", "deriveBits"]).then (
            function(kekKey) {
                kaPrivate = kekKey;
                return window.crypto.subtle.importKey("jwk", cwk2jwk(that.FindAttribute("epk")), importPublicAlgorithm, false, []);
            }
        ).then (
            function(pubData) {
                deriveAlgorithm["public"] = pubData;
                return _deriveKey(deriveAlgorithm, kaPrivate, wrapAlgorithm, true, ["unwrapKey"]);
            }
        ).then (
            function(wrapKey) {
                return window.crypto.subtle.unwrapKey("raw", that.cipherText, wrapKey, wrapAlgorithm, cekAlgorithm, false, ["decrypt"]);
            }
        );
    }

    return new Promise(function (myResolve, myReject) {
        var prom;
        
        switch (kekAlg) {
        case "RSA-OAEP-256":
            if (key["kty"] != "RSA") {
                myResolve(null);
                return null;
            }
            importAlgorithm = {"name":"RSA-OAEP", "hash":{ "name":"SHA-256"}};
            wrapAlgorithm = {"name":"RSA-OAEP"};
            prom = window.crypto.subtle.importKey("jwk", key, importAlgorithm, false, ["decrypt", "unwrapKey"]).then (
                function(kekKey) {
                    return window.crypto.subtle.unwrapKey("raw", that.cipherText, kekKey, wrapAlgorithm, cekAlgorithm, false, ["decrypt"]);
                }
            );
            break;

        case "ECDH-ES+A128KW":
            if (key["kty"] != "EC") {
                myResolve(null);
                return null;
            }
            importPrivateAlgorithm = { "name":"ECDH", "namedCurve":key["crv"] };
            importPublicAlgorithm = { "name":"ECDH", "namedCurve":key["crv"] };
            deriveAlgorithm = that._buildConcat(kekAlg, 128);
            wrapAlgorithm = {"name":"AES-KW", "length":128};
            prom = keyAgree();
            break;

        default:
            myResolve(null);
            break;
        }

        return prom.then(
            function(val) {
                myResolve(val);
            },  
            function(val) {
                myResolve(null);
            }
        );
    });
};


Recipient.prototype._buildConcat = function(alg, cbitKey)
{
    function _prefixLength(x)
    {
        var ui8Array = new Uint8Array(x.length + 4);
        if (x.length > 255) throw "Internal Error";
        ui8Array.set([0, 0, 0, t.length], 0);
        ui8Array.set(t, 4);
        return ui8Array;
    }

    var deriveAlgorithm = {"name":"CONCAT", "hash":{"name":"SHA-256"}};
    
    var t = Utf8.encode(alg);
    deriveAlgorithm["algorithmId"] = _prefixLength(t);

    t = this.FindAttribute("apu");
    if (t === null) t = new Uint8Array(0);
    deriveAlgorithm["partyUInfo"] = _prefixLength(t);

    t = this.FindAttribute("apv");
    if (t === null) t = new Uint8Array(0);
    deriveAlgorithm["partyVInfo"] = _prefixLength(t);

    t = new Uint8Array(4);
    t[3] = cbitKey % 256;
    t[2] = cbitKey / 256;
    deriveAlgorithm["publicInfo"] = t;

    return deriveAlgorithm;
};

function _deriveKey(deriveAlgorithm, privateKey, wrapAlgorithm, exportable, usages)
{
    if (deriveAlgorithm["name"] != "CONCAT") return window.crypto.subtle.deriveKey(deriveAlgorithm, privateKey, wrapAlgorithm, exportable, usages);

    return window.crypto.subtle.deriveBits({"name":"ECDH", "public":deriveAlgorithm["public"]}, privateKey, null).then (
        function(secret) {
            //  Build the buffer is a pain
            var f = [];
            f.push(new Uint8Array([0, 0, 0, 1]));
            f.push(new Uint8Array(secret));
            f.push(deriveAlgorithm["algorithmId"]);
            f.push(deriveAlgorithm["partyUInfo"]);
            f.push(deriveAlgorithm["partyVInfo"]);
            f.push(deriveAlgorithm["publicInfo"]);
            var i;
            var l = 0;
            for (i=0; i<f.length; i++) l += f[i].length;
            var rgbData = new Uint8Array(l);
            l = 0;
            for (i=0; i<f.length; i++) {
                rgbData.set(f[i], l);
                l += f[i].length;
            }

            return window.crypto.subtle.digest({"name":"SHA-256"}, rgbData);
        }
    ).then(
        function(digest) {
            digest = digest.slice(wrapAlgorithm["length"]/8);
            return window.crypto.subtle.importKey("raw", digest, wrapAlgorithm, true, usages);
        }
    );
};

Recipient.prototype.Encrypt = function(cek) {
    var that = this;
    var deriveAlgorithm;
    var generateAlgorithm;
    var importAlgorithm;
    var wrapAlgorithm;

    function keyAgree()
    {
        var kaPrivate;

        return window.crypto.subtle.importKey("jwk", that.key, importAlgorithm, false, []).then (
            function(kekKey) {
                deriveAlgorithm["public"] = kekKey;
                return window.crypto.subtle.generateKey(generateAlgorithm, true, ["deriveKey", "deriveBits"]);
            }
        ).then (
            function(genKey) {
                kaPrivate = genKey;
                return window.crypto.subtle.exportKey("jwk", genKey.publicKey);
            }
        ).then (
            function(pubData) {
                that.AddUnprotected("epk", jwk2cwk(pubData, true));
                return _deriveKey(deriveAlgorithm, kaPrivate.privateKey, wrapAlgorithm, true, ["wrapKey"]);
            }
        ).then (
            function(wrapKey) {
                return window.crypto.subtle.wrapKey("raw", cek, wrapKey, wrapAlgorithm);
            }
        ).then (
            function(val) {
                that.cipherText = val;
                return val;
            }
        );
    }

    function keyWrap() {
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
                );
            }
        );
    }

    var alg = this.FindAttribute("alg");

    switch (alg) {
    case "RSA-OAEP-256":
        importAlgorithm = { "name":"RSA-OAEP", "hash":{ "name":"SHA-256"}};
        wrapAlgorithm = {"name":"RSA-OAEP"};
        return keyWrap();

    case "ECDH-ES+A128KW":
        importAlgorithm = { "name":"ECDH", "namedCurve":this.key["crv"] };
        generateAlgorithm = { "name":"ECDH", "namedCurve":this.key["crv"] };
        deriveAlgorithm = this._buildConcat(alg, 128);
        wrapAlgorithm = {"name":"AES-KW", "length":128};
        return keyAgree();

    default:
        throw "Unrecognized algorithm";
    }

};

var SignMessage = function(content) {

    if ((content === null) || (content == undefined)) {
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
    this.signerList = [];
};

SignMessage.prototype = {

    AddProtected: function(key, value) {
        if (this.objProtected === null) this.objProtected = {};
        this.objProtected[key] = value;
        if (key in this.objUnprotected) delete this.objUnprotected[key];
    },

    AddUnprotected: function(key, value) {
        if (this.objUnprotected === null) this.objUnprotected = {};
        this.objUnprotected[key] = value;
        if (key in this.objProtected) delete this.objProtected[key];
    },

    AddSigner: function(signer) {
        this.signerList.push(signer);
    },

    EncodeToBytes: function() {
        var promise = this.EncodeToCBOR();
        return promise.then(
            function(val) {
                return CBOR.encode(val); } );
    },

    DecodeFromCBOR: function(cborValue) {
        if (cborValue < 6) throw "Invalid CBOR object";

        if (cborValue[0] === null) this.objProtected = {};
        else this.objProtected = CBOR.decode(cborValue[0]);

        if (cborValue[1] === null) this.objUnprotected = {};
        else this.objUnprotected = cborValue[1];

        this.plainText = cborValue[2];

        if (cborValue.length == 4) {
            this.signerList = cborValue[3].map(function(r) {
                var signer = new Signer();
                signer.DecodeFromCBOR(r);
                return signer;
            });
        }
        else {
            var signer = new Signer();
            signer.DecodeFromCBOR(cborValue.slice(3));
            this.signerList.push(signer);
        }
    },

    EncodeToCBOR: function() { //  method that turns the structure into CBOR
        var that = this;

        function _fillArray() {
            var cborValue = [];

            if (Object.keys(this.objProtected).length === 0) cborValue[0] = null;
            else cborValue[0] = CBOR.encode(this.objProtected);

            if (Object.keys(this.objUnprotected).length > 0) cborValue[1] = this.objUnprotected;
            else cborValue[1] = null;                            

            cborValue[2] = new Uint8Array(this.plainText);

            if (this.signerList.length == 1) {
                var r = this.signerList[0].EncodeToCBOR();
                cborValue.push.apply(cborValue, r);
            }
            else if (this.signerList.length === 0) {
                cborValue[5] = null;
            }
            else {
                cborValue[3] = this.signerList.map(function(r) {
                    return r.EncodeToCBOR();
                });
            }
            return cborValue;
        }

        var promiseSigners = this.signerList.map(function(r) {
            return r.Sign(that); 
        });

        return Promise.all(promiseSigners).
            then( function() { 
                return _fillArray.call(that); 
            },
                function(errMsg) {
                    return errMsg;
                }
                );
    },

    Verify: function(key) {
        var that = this;
        
        var promises = this.signerList.map(function(r) {
            return r.Verify(key, that);
        });

        return Promise.all(promises).then(
            function(resultArray) {
                return resultArray;
            }
        );
    },

    FindAttribute : function(key) {
        if ((this.objProtected !== null) && (key in this.objProtected)) return this.objProtected[key];
        if ((this.objUnprotected !== null) && (key in this.objUnprotected)) return this.objUnprotected[key];
        return null;
    },

    SetContent: function(content) {
        if ((typeof content == "string") || (content instanceof String)) {
            this.plainText = Utf8.encode(content);
        }
        else if ((content instanceof Int8Array) || (content instanceof Uint8Array)) {
            this.plainText = content;
        }
        else throw "Bad content type";
    }
};

var Signer = function(key, algorithm) {
    this.objProtected  =  {};
    this.objUnprotected  =  {};
    this.key = key;
    if (typeof algorithm == "string") this.AddProtected("alg", algorithm);
};

Signer.prototype = {
    AddProtected: function(key, value) {
        if (this.objProtected === null) this.objProtected = {};
        this.objProtected[key] = value;
        if (key in this.objUnprotected) delete this.objUnprotected[key];
    },

    AddUnprotected: function(key, value) {
        if (this.objUnprotected === null) this.objUnprotected = {};
        this.objUnprotected[key] = value;
        if (key in this.objProtected) delete this.objProtected[key];
    },

    DecodeFromCBOR: function(cborValue) {
        if (cborValue.length != 3) throw "Illegal CBOR Signature Structure";

        if (cborValue[0] === null) this.objProtected = {};
        else this.objProtected = CBOR.decode(cborValue[0]);

        if (cborValue[1] === null) this.objUnprotected = {};
        else this.objUnprotected = cborValue[1];

        this.signature = cborValue[2];
    },

    EncodeToCBOR: function() { //  method that turns the structure into CBOR
        var cborValue = [];

        if (Object.keys(this.objProtected).length === 0) cborValue[0] = null;
        else cborValue[0] = CBOR.encode(this.objProtected);

        if (Object.keys(this.objUnprotected).length > 0) cborValue[1] = this.objUnprotected;
        else cborValue[1] = null;                            

        cborValue[2] = this.signature;

        return cborValue;
    },

    Sign: function(message) {
        var that = this;
        var cborValue = [];

        if (Object.keys(message.objProtected).length === 0) cborValue[0] = null;
        else cborValue[0] = CBOR.encode(mesasge.objProtected);

        cborValue[1] = message.plainText;

        if (Object.keys(this.objProtected).length === 0) cborValue[2] = null;
        else cborValue[2] = CBOR.encode(this.objProtected);

        var data = CBOR.encode(cborValue);

        var signParameters;
        var importAlg;

        var alg = this.FindAttribute("alg");

        switch (alg) {
        case "ES521":
            signParameters = {"name":"ECDSA", "hash":{"name":"SHA-512"}};
            importAlg = {"name":"ECDSA", "namedCurve":this.key["crv"]};
            break;

        case "RS256":
            signParameters = {"name":"RSASSA-PKCS1-v1_5"};
            importAlg = {"name":"RSASSA-PKCS1-v1_5", "hash":{"name":"SHA-256"}};
            break;

        case "PS256":
            signParameters = {"name":"RSA-PSS", "saltLength":256/8};
            importAlg = {"name":"RSA-PSS", "hash":{"name":"SHA-256"}};
            break;

        default:
            throw "Unknown signature algorithm";
        }

//        if (this.key instanceof CryptoKey) {
//            return window.crypto.subtle.sign(signParameters, this.key, data);
//        }

        return window.crypto.subtle.importKey("jwk", this.key, importAlg, false, ["sign"]).
            then(
                function(sigKey) {
                    return window.crypto.subtle.sign(signParameters, sigKey, data);
                }
            ).then(
                function(sigVal) {
                    that.signature = sigVal;
                    return sigVal;
                }
            );
    },

    Verify: function(key, message) {
        var that = this;
        var cborValue = [];

        function _falsePromise()
        {
            return new Promise(function(myResolve, myReject) { myResolve(false); });
        };

        if (Object.keys(message.objProtected).length === 0) cborValue[0] = null;
        else cborValue[0] = CBOR.encode(mesasge.objProtected);

        cborValue[1] = message.plainText;

        if (Object.keys(this.objProtected).length === 0) cborValue[2] = null;
        else cborValue[2] = CBOR.encode(this.objProtected);

        var data = CBOR.encode(cborValue);

        var signParameters;
        var importAlg;

        var alg = this.FindAttribute("alg");
        if (key["alg"] !== undefined) {
            if (key["alg"] != alg) return _falsePromise();
        }

        switch (alg) {
        case "ES521":
            if (key["kty"] != "EC") return _falsePromise();
            signParameters = {"name":"ECDSA", "hash":{"name":"SHA-512"}};
            importAlg = {"name":"ECDSA", "namedCurve":key["crv"]};
            break;

        case "RS256":
            if (key["kty"] != "RSA") return _falsePromise();
            signParameters = {"name":"RSASSA-PKCS1-v1_5"};
            importAlg = {"name":"RSASSA-PKCS1-v1_5", "hash":{"name":"SHA-256"}};
            break;

        case "PS256":
            if (key["kty"] != "RSA") return _falsePromise();
            signParameters = {"name":"RSA-PSS", "saltLength":256/8};
            importAlg = {"name":"RSA-PSS", "hash":{"name":"SHA-256"}};
            break;

        default:
            return _falsePromise();
        }

        if (this.key instanceof CryptoKey) {
            return window.crypto.subtle.sign(signParameters, this.key, data);
        }

        return window.crypto.subtle.importKey("jwk", key, importAlg, false, ["verify"]).
            then(
                function(sigKey) {
                    return window.crypto.subtle.verify(signParameters, sigKey, that.signature, data);
                },
                function(error) {
                    return false;
                }
            ).then (
                function(retVal) { return retVal; },
                function(retValue) {
                    return false;
                });
    },

    FindAttribute : function(key) {
        if ((this.objProtected !== null) && (key in this.objProtected)) return this.objProtected[key];
        if ((this.objUnprotected !== null) && (key in this.objUnprotected)) return this.objUnprotected[key];
        return null;
    }

};

function jwk2cwk(jwkIn, ephemeral)
{
    if ((ephemeral === null) || (ephemeral == undefined)) ephemeral = false;
    else if (typeof ephemeral != "boolean") throw "Incorrect type for ephemeral";

    var cwk = {};
    var kty = jwkIn["kty"];

    for (var key in jwkIn) {
        if (jwkIn.hasOwnProperty(key)) {
            if (ephemeral) {
                switch (key) {
                case "kty":
                case "crv":
                case "x":
                case "y":
                    break;

                default:
                    continue;
                    break;
                }
            }
        }

        switch (key) {
        case "kty":
        case "use":
        case "key_ops":
        case "alg":
        case "kid":
            cwk[key] = jwkIn[key];
            break;

        case "x5u":
        case "x5t":
        case "x5t#S256":
            cwk[key] = Utf8.b64toU8(jwkIn[key]);
            break;

        case "x5c":
            break;

        default:
            switch (kty) {
            case "RSA":
                switch (key) {
                case "n":
                case "e":
                case "d":
                case "p":
                case "q":
                case "dp":
                case "dq":
                case "qi":
                    cwk[key] = Utf8.b64toU8(jwkIn[key]);
                    break;

                default:
                    cwk[key] = jwkIn[key];
                    break;
                }
                break;

            case "EC":
                switch (key) {
                case "x":
                case "y":
                    cwk[key] = Utf8.b64toU8(jwkIn[key]);
                    break;

                case "crv":
                default:
                    cwk[key] = jwkIn[key];
                    break;
                }
                break;

            case "oct":
                switch (key) {
                case "k":
                    cwk[key] = Utf8.b64toU8(jwkIn[key]);
                    break;

                default:
                    cwk[key] = jwkIn[key];
                    break;
                }
                break;

            default:
                throw "Invalid structure for key";
            }
            break;
        }
    }

    return cwk;
}

function cwk2jwk(cwkIn)
{
    var jwk = {};
    for (var key in cwkIn) {
        if (cwkIn.hasOwnProperty(key)) {
            var val = cwkIn[key];

            if (val instanceof ArrayBuffer) {
                jwk[key] = Utf8.U8toB64(new Uint8Array(val));
            }
            else if (val instanceof Uint8Array) {
                jwk[key] = Utf8.U8toB64(val);
            }
            else {
                jwk[key] = val;
            }
        }
    }

    return jwk;
}
