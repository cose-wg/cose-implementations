/**
*
*  UTF-8 data encode / decode
*  http://www.webtoolkit.info/
*
**/
var Utf8 = {
    // public method for url encoding
    encode : function (string) {
        string = string.replace(/\r\n/g,"\n");
        var utftext = "";
        for (var n = 0; n < string.length; n++) {
            var c = string.charCodeAt(n);
            if (c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
        }
        return this.str2ab(utftext);
    },
    // public method for url decoding
    decode : function (utftext) {
        var string = "";
        var i = 0;
        var c = c1 = c2 = 0;
        while ( i < utftext.length ) {
            c = utftext.charCodeAt(i);
            if (c < 128) {
                string += String.fromCharCode(c);
                i++;
            }
            else if((c > 191) && (c < 224)) {
                c2 = utftext.charCodeAt(i+1);
                string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                i += 2;
            }
            else {
                c2 = utftext.charCodeAt(i+1);
                c3 = utftext.charCodeAt(i+2);
                string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }
        }
        return string;
    },
    ab2str: function(buf) {
        return String.fromCharCode.apply(null, new Uint8Array(buf));
    },
    str2ab: function(str) {
        var buf = new ArrayBuffer(str.length); // 1 bytes for each char
        var bufView = new Uint8Array(buf);
        for (var i=0, strLen=str.length; i<strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return new Uint8Array(buf);
    },
    ab2hex: function(buf) {
        var chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
        var str = "";
        var dataview = new DataView(buf);
        
        for (var i=0; i<buf.byteLength; i++) {
            var byteX = dataview.getUint8(i);
            str += chars[byteX >> 4];
            str += chars[byteX & 0xf];
            str += " ";
        }
        return str;
    },
    b64toU8: function(buf) {
        buf = buf.split("-").join("+");
        buf = buf.split("_").join("/");

        var u8_2 = new Uint8Array(atob(buf).split("").map(function(c) { return c.charCodeAt(0); }));
        return u8_2;
    },
    U8toB64: function(buf) {
        var ba = btoa(String.fromCharCode.apply(null, buf));
        ba = ba.split("+").join("-");
        ba = ba.split("/").join("_");
        ba = ba.split("=");
        return ba[0];
    }
};

