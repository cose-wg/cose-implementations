using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace COSE
{
    public class SignMessage : Message
    {
        CBORObject obj;

         List<Signer> signerList = new List<Signer>();
         byte[] rgbContent;

        public void AddSigner(Signer sig)
        {
            signerList.Add(sig);
        }

        override public byte[] EncodeToBytes()
        {
            CBORObject obj3;

            obj = CBORObject.NewArray();
            obj.Add(0);  // Tag as an Signed item

            obj3 = EncodeToCBORObject();

            for (int i = 0; i < obj3.Count; i++) obj.Add(obj3[i]);

            return obj.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            CBORObject obj = CBORObject.NewArray();

            if (objProtected != null) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(objProtected);
            obj.Add(objUnprotected); // Add unprotected attributes

            obj.Add(rgbContent);

            if (signerList.Count == 1) {
                CBORObject recipient = signerList[0].EncodeToCBORObject(obj[0], rgbContent);

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (signerList.Count > 1) {
                CBORObject signers = CBORObject.NewArray();

                foreach (Signer key in signerList) {
                    signers.Add(key.EncodeToCBORObject(obj[0], rgbContent));
                }
                obj.Add(signers);
            }
            else {
                obj.Add(null);      // No recipients - set to null
            }
            return obj;
        }

        public void SetContent(byte[] keyBytes)
        {
            rgbContent = keyBytes;
        }

        public void SetContent(string contentString)
        {
            rgbContent = UTF8Encoding.ASCII.GetBytes(contentString);
        }

    }

    public class Signer
    {
        CBORObject objUnprotected;
        CBORObject objProtected;

        Key keyToSign;

                public Signer(Key key, string algorithm = null)
        {
            if (algorithm != null) AddUnprotected("alg", algorithm);
            if (key.ContainsName("kid")) AddUnprotected("kid", key.AsObject("kid"));

            if (key.ContainsName("use")) {
                    string usage = key.AsString("use");
                    if (usage != "sig") throw new Exception("Key cannot be used for encrytion");
            }

            if (key.ContainsName("key_ops")) { 
                CBORObject usageObject = key.AsObject("key_ops");
                bool validUsage = false;

                if (usageObject.Type != CBORType.Array) throw new Exception("key_ops is incorrectly formed");
                for (int i = 0; i < usageObject.Count; i++) {
                    switch (usageObject[i].AsString()) {
                    case "encrypt":
                    case "keywrap":
                        validUsage = true;
                        break;
                    }
                }
                string usage = key.AsString("key_ops");
                if (!validUsage) throw new Exception("Key cannot be used for encryption");
            }

            keyToSign = key;
        }


        public void AddProtected(string name, string value)
        {
            if (objProtected == null) objProtected = CBORObject.NewMap();
            if (objProtected.ContainsKey(name)) objProtected.Set(name, value);
            else objProtected.Add(name, value);
            //           if ((objUnprotected != null) && (objUnprotected.ContainsKey(name))) objUnprotected.Remove(new CBORObject(CBORType.TextString,  name));
        }

        public void AddUnprotected(string name, string value)
        {
            if (objUnprotected == null) objUnprotected = CBORObject.NewMap();
            if (objUnprotected.ContainsKey(name)) objUnprotected.Set(name, value);
            else objUnprotected.Add(name, value);
            //           if ((objProtected != null) && (objProtected.ContainsKey(name))) objProtected.Remove(name);
        }

        public void AddUnprotected(string name, CBORObject obj)
        {
            if (objUnprotected == null) objUnprotected = CBORObject.NewMap();
            objUnprotected.Add(name, obj);
        }

        public CBORObject EncodeToCBORObject(CBORObject bodyAttributes, byte[] body)
        {
            CBORObject obj = CBORObject.NewArray();

            if (objProtected != null) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(objProtected);
            obj.Add(objUnprotected); // Add unprotected attributes

            CBORObject signObj = CBORObject.NewArray();
            signObj.Add(bodyAttributes);
            signObj.Add(body);
            signObj.Add(obj[0]);

            obj.Add(Sign(signObj.EncodeToBytes()));
        
            return obj;
        }

        private byte[] Sign(byte[] bytesToBeSigned)
        {
            string alg = null; // Get the set algorithm or infer one
            try {
                alg = objUnprotected["alg"].AsString();
            }
            catch (Exception) {
                try {
                    alg = objProtected["alg"].AsString();
                }
                catch (Exception) {
                    ;
                }
            }

            if (alg == null) {
                switch (keyToSign.AsString("kty")) {
                case "RSA":
                    alg = "PS256";
                    break;

                case "EC":
                    switch (keyToSign.AsString("crv")) {
                    case "P-256":
                        alg = "ES256";
                        break;

                    case "P-384":
                        alg = "ES384";
                        break;

                    case "P-521":
                        alg = "ES512";
                        break;

                    default:
                        throw new Exception("Unknown curve");
                    }
                    break;

                default:
                    throw new Exception("Unknown or unsupported key type " + keyToSign.AsString("kty"));
                }
            }

            IDigest digest;
            IDigest digest2;

            switch (alg) {
            case "RS256":
            case "ES256":
            case "PS256":
                digest = new Sha256Digest();
                digest2 = new Sha256Digest();
                break;

            case "RS384":
            case "ES384":
            case "PS384":
                digest = new Sha384Digest();
                digest2 = new Sha384Digest();
                break;

            case "RS512":
            case "ES512":
            case "PS512":
                digest = new Sha512Digest();
                digest2 = new Sha512Digest();
                break;

            default:
                throw new Exception("Unknown signature algorithm");
            }


            switch (alg) {
            case "PS256":
            case "PS384":
            case "PS512":
                {
                    PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());
                    RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(ConvertBigNum(keyToSign.AsObject("n")), ConvertBigNum(keyToSign.AsObject("e")), ConvertBigNum(keyToSign.AsObject("d")), ConvertBigNum(keyToSign.AsObject("p")), ConvertBigNum(keyToSign.AsObject("q")), ConvertBigNum(keyToSign.AsObject("dp")), ConvertBigNum(keyToSign.AsObject("dq")), ConvertBigNum(keyToSign.AsObject("qi")));

                    signer.Init(true, prv);
                    signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                    return signer.GenerateSignature();
                }

            case "ES256":
            case "ES384":
            case "ES512": 
                {
                    SecureRandom random = new SecureRandom();

                    X9ECParameters p = NistNamedCurves.GetByName(keyToSign.AsString("crv"));
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                    ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(keyToSign.AsObject("d")), parameters);
                    ParametersWithRandom param = new ParametersWithRandom(privKey, random);

                    ECDsaSigner ecdsa = new ECDsaSigner();
                    ecdsa.Init(true, param);

                    BigInteger[] sig = ecdsa.GenerateSignature(bytesToBeSigned);
                    byte[] r = sig[0].ToByteArray();
                    byte[] s = sig[1].ToByteArray();
                    byte[] sigs = new byte[r.Length + s.Length];
                    Array.Copy(r, sigs, r.Length);
                    Array.Copy(s, 0, sigs, r.Length, s.Length);

                    return sigs;
                }
            }
            return null;
        }

        private Org.BouncyCastle.Math.BigInteger ConvertBigNum(PeterO.Cbor.CBORObject cbor)
        {
            byte[] rgb = cbor.GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) rgb2[i + 2] = rgb[i];

            return new Org.BouncyCastle.Math.BigInteger(rgb2);
        }

    }
}
