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

    EncodeToBytes: function() {
        var promise = EncodeToCBOR();
        return promise.then(function(val) { resolve(CBOR.encode(val)); } );
    },

    EncodeToCBOR: function() { //  method that turns the structure into CBOR
        var cborValue = [];

        var promiseEncrypt = null;

        if (this.cipherText == null) promiseEncrypt = this.Encrypt();
        else {
            promiseEncrypt = new Promise();
            promiseEncrypt.resolve(true);
        }

        var that = this;
        return promiseEncrypt.then(function() {
            if (Object.keys(that.objProtected).length == 0) cborValue[0] = null;
            else cborValue[0] = CBOR.encode(that.objProtected);

            if (Object.keys(that.objUnprotected).length > 0) cborValue[1] = that.objUnprotected;
            else cborValue[1] = null;                            

            cborValue[2] = that.iv;

            cborValue[3] = that.aad;

            cborValue[4] = that.cipherText;

            if (that.recipientList.length == 1) {
                var r = that.recipientList[0].EncodeToCBOR();
                cborValue.push.apply(cborValue, r);
            }
            else if (that.recipientList.length == 0) {
                cborValue[5] = null;
            }
            else {
                cborValue[5] = [];
                for (var recipient in that.recipientList) {
                    cborValue[5].push(recipient.EncodeToCBOR());
                }
            }

            return cborValue;
        });
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
                var recips = [];
                for (var i=0; i<that.recipientList.length; i++) {
                    recips.push(that.recipientList[i].Encrypt(that.cek));
                }
                if (recips.length == 0) myResolve(true);
                else Promise.all(recips).then(function(recipVals) {
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
        ).then(function(value) {that.cipherText = value; return value;},
               console.error.bind(console, "Unable to encrypt"));        
    }

}

var Recipient = function(key, algorithm) {
    EncryptMessage.call(this);
    this.key = key;
    if (typeof algorithm == "string") this.AddUnprotected("alg", algorithm);
}

Recipient.prototype = Object.create(EncryptMessage.prototype);

Recipient.prototype.Encrypt = function(cek) {
    var that = this;

    var alg = this.FindAttribute("alg");
    var importAlgorithm;
    var wrapAlgorithm;

    switch (alg) {
    case "RSA-OAEP-256":
        importAlgorithm = { "name":"RSA-OAEP", "hash":"SHA-256"};
        wrapAlgorithm = {"name":"RSA-OAEP"};
        break;

    default:
        throw "Unrecognized algorithm";
    }

    var that = this;
    return window.crypto.subtle.importKey("jwk", this.key, importAlgorithm, false, ["encrypt"]).then(
        function(kekKey) {
            return window.crypto.subtle.wrapKey("raw", cek, kekKey, that.wrapAlgorithm);
        }
    ).then(
        function(val) { 
            that.cipherText = val;
            console.log("Successful wrap"); return val;},
        function(val) { 
            console.error.bind("Failed wrap"); return val;});

}
