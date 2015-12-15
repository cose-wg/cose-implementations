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
        List<Signer> signerList = new List<Signer>();
        byte[] rgbContent;

        public void AddSigner(Signer sig)
        {
            signerList.Add(sig);
        }

        public byte[] BEncodeToBytes()
        {
            CBORObject obj2 = BEncodeToCBORObject();

            return obj2.EncodeToBytes();
        }

        override public byte[] EncodeToBytes()
        {
            CBORObject obj3;

            obj3 = EncodeToCBORObject();

            return obj3.EncodeToBytes();
        }

        public CBORObject BEncodeToCBORObject()
        {
            CBORObject objX = EncodeToCBORObject();
            CBORObject obj = CBORObject.NewMap();

            if (objX[2] != null) obj[CBORObject.FromObject(1)] = objX[2];
            if (objX[3] != null) {
                CBORObject obj3 = CBORObject.NewArray();
                obj[CBORObject.FromObject(2)] = obj3;
                for (int i = 0; i < objX[3].Count; i++) {
                    CBORObject obj2 = CBORObject.NewMap();
                    obj3.Add(obj2);
                    obj2[CBORObject.FromObject(3)] = objX[3][i][2];
                    obj2[CBORObject.FromObject(4)] = objX[3][i][1];
                    if (objX[3][i][0] != null) {
                        obj2[CBORObject.FromObject(5)] = objX[3][i][0];
                    }
                }
            }
            return obj;
        }

        public CBORObject EncodeToCBORObject()
        {
            CBORObject obj;
            CBORObject obj3;

#if USE_ARRAY
            obj = CBORObject.NewArray();
#else
            obj = CBORObject.NewMap();
            obj.Add(RecordKeys.MsgType, 1);  // Tag as an Signed item
#endif

            obj3 = Encode();

#if USE_ARRAY
            for (int i = 0; i < obj3.Count; i++) obj.Add(obj3[i]);
#else
            foreach (CBORObject key in obj3.Keys) obj.Add(key, obj3[key]);
#endif

            if (m_useTag) return CBORObject.FromObjectAndTag(obj, (int) Tags.Signed);
            return obj;
        }

        public CBORObject Encode()
        {
            CBORObject obj;

#if USE_ARRAY
            obj = CBORObject.NewArray();

            if ((objProtected != null) && (objProtected.Count > 0)) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(new byte[0]);

            if ((objUnprotected == null) || (objUnprotected.Count == 0)) obj.Add(CBORObject.NewMap());
            else obj.Add(objUnprotected); // Add unprotected attributes

            obj.Add(rgbContent);

            if ((signerList.Count == 1) && !this.m_forceArray) {
                CBORObject recipient = signerList[0].EncodeToCBORObject(obj[0], rgbContent);

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (signerList.Count > 0) {
                CBORObject signers = CBORObject.NewArray();

                foreach (Signer key in signerList) {
                    signers.Add(key.EncodeToCBORObject(obj[0], rgbContent));
                }
                obj.Add(signers);
            }
            else {
                obj.Add(null);      // No recipients - set to null
            }
#else
            obj = CBORObject.NewMap();

            CBORObject cborProtected = CBORObject.Null;
            if ((objProtected != null) && (objProtected.Count > 0)) {
                byte[] rgb = objProtected.EncodeToBytes();
                obj.Add(RecordKeys.Protected,  rgb);
                cborProtected = CBORObject.FromObject(rgb);
            }

            if ((objUnprotected != null) && (objUnprotected.Count > 0))  obj.Add(RecordKeys.Unprotected, objUnprotected); // Add unprotected attributes

            obj.Add(RecordKeys.Payload, rgbContent);

            if (signerList.Count > 0) {
                CBORObject signers = CBORObject.NewArray();

                foreach (Signer key in signerList) {
                    signers.Add(key.EncodeToCBORObject(cborProtected, rgbContent));
                }
                obj.Add(RecordKeys.Signatures, signers);
            }
#endif
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

    public class Signer : Attributes
    {
        Key keyToSign;
        byte[] rgbSignature = null;
        protected string context = "Signature";

        public Signer(Key key, CBORObject algorithm = null)
        {
            if (algorithm != null) AddAttribute(HeaderKeys.Algorithm, algorithm, false);
            if (key.ContainsName(CoseKeyKeys.KeyIdentifier)) AddUnprotected(HeaderKeys.KeyId, key[CoseKeyKeys.KeyIdentifier]);

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "sig") throw new Exception("Key cannot be used for encrytion");
            }

            if (key.ContainsName(CoseKeyKeys.Key_Operations)) {
                CBORObject usageObject = key[CoseKeyKeys.Key_Operations];
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

        public CBORObject EncodeToCBORObject()
        {
            if (rgbSignature == null) {
                throw new Exception("Must be signed already to use this function call");
            }
            return EncodeToCBORObject(null, null);
        }

        public CBORObject EncodeToCBORObject(CBORObject bodyAttributes, byte[] body)
        {
#if USE_ARRAY
            CBORObject obj = CBORObject.NewArray();

            CBORObject cborProtected = CBORObject.FromObject(new byte[0]);
            if ((objProtected != null) && (objProtected.Count > 0)) {
                byte[] rgb = objProtected.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }
            obj.Add(cborProtected);

            if ((objUnprotected == null)) obj.Add(CBORObject.NewMap());
            else obj.Add(objUnprotected); // Add unprotected attributes

            if (rgbSignature == null) {
                CBORObject signObj = CBORObject.NewArray();
                signObj.Add(context);
                signObj.Add(bodyAttributes);
                signObj.Add(body);
                signObj.Add(cborProtected);
                signObj.Add(new byte[0]); // External AAD
                signObj.Add(obj[0]);

                rgbSignature = Sign(signObj.EncodeToBytes());
            }
            obj.Add(rgbSignature);
#else
            CBORObject obj = CBORObject.NewMap();

            CBORObject cborProtected = CBORObject.FromObject(new byte[0]);
            if ((objProtected != null) && (objProtected.Count > 0)) {
                byte[] rgb = objProtected.EncodeToBytes();
                obj.Add(RecordKeys.Protected, rgb);
                cborProtected = CBORObject.FromObject(rgb);
            }
            if ((objUnprotected != null) && (objUnprotected.Count > 0)) obj.Add(RecordKeys.Unprotected, objUnprotected); // Add unprotected attributes

            CBORObject signObj = CBORObject.NewArray();
            signObj.Add(bodyAttributes);
            signObj.Add(cborProtected);
            signObj.Add(new byte[0]); // External AAD
            signObj.Add(body);

            obj.Add(RecordKeys.Signature, Sign(signObj.EncodeToBytes()));
#endif
            return obj;
        }

        private byte[] Sign(byte[] bytesToBeSigned)
        {
            CBORObject alg = null; // Get the set algorithm or infer one

            alg = FindAttribute(HeaderKeys.Algorithm);

            if (alg == null) {
                if (keyToSign[CoseKeyKeys.KeyType].Type == CBORType.Number) {
                    switch ((GeneralValuesInt) keyToSign[CoseKeyKeys.KeyType].AsInt32()) {
                    case GeneralValuesInt.KeyType_RSA:
                        alg = CBORObject.FromObject("PS256");
                        break;

                    case GeneralValuesInt.KeyType_EC2:
                        if (keyToSign[CoseKeyParameterKeys.EC_Curve].Type == CBORType.Number) {
                            switch ((GeneralValuesInt) keyToSign[CoseKeyParameterKeys.EC_Curve].AsInt32()) {
                            case GeneralValuesInt.P256:
                                alg = AlgorithmValues.ECDSA_256;
                                break;

                            case GeneralValuesInt.P521:
                                alg = AlgorithmValues.ECDSA_512;
                                break;

                            default:
                                throw new CoseException("Unknown curve");
                            }
                        }
                        else if (keyToSign[CoseKeyParameterKeys.EC_Curve].Type == CBORType.TextString) {
                            switch (keyToSign[CoseKeyParameterKeys.EC_Curve].AsString()) {
                            case "P-384":
                                alg = CBORObject.FromObject("ES384");
                                break;

                            default:
                                throw new CoseException("Unknown curve");
                            }
                        }
                        else throw new CoseException("Curve is incorrectly encoded");
                        break;

                    default:
                        throw new Exception("Unknown or unsupported key type " + keyToSign.AsString("kty"));
                    }
                }
                else if (keyToSign[CoseKeyKeys.KeyType].Type == CBORType.TextString) {
                    throw new CoseException("Unknown or unsupported key type " + keyToSign[CoseKeyKeys.KeyType].AsString());
                }
                else throw new CoseException("Key type is not correctly encoded");
                objUnprotected.Add(HeaderKeys.Algorithm, alg);
            }

            IDigest digest;
            IDigest digest2;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "ES384":
                case "PS384":
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                default:
                    throw new Exception("Unknown signature algorithm");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.RSA_PSS_256:
                    digest = new Sha256Digest();
                    digest2 = new Sha256Digest();
                    break;

                case AlgorithmValuesInt.ECDSA_512:
                case AlgorithmValuesInt.RSA_PSS_512:
                    digest = new Sha512Digest();
                    digest2 = new Sha512Digest();
                    break;

                default:
                    throw new CoseException("Unknown signature algorith");
                }
            }
            else throw new CoseException("Algorthm incorrectly encoded");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "PS384":
                    {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, Message.GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.GenerateSignature();
                    }

                case "ES384":
                    {
                        SecureRandom random = Message.GetPRNG();

                        X9ECParameters p = keyToSign.GetCurve();
                        ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(keyToSign[CoseKeyParameterKeys.EC_D]), parameters);
                        ParametersWithRandom param = new ParametersWithRandom(privKey, Message.GetPRNG());

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
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_PSS_256:
                case AlgorithmValuesInt.RSA_PSS_512:
                    {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, Message.GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.GenerateSignature();
                    }

                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.ECDSA_512:
                    {
                        SecureRandom random = Message.GetPRNG();

                        X9ECParameters p = keyToSign.GetCurve();
                        ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(keyToSign[CoseKeyParameterKeys.EC_D]), parameters);
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

                default:
                    throw new CoseException("Unknown Algorithm");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

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

    public class CounterSignature : Signer
    {
        Message m_msgToSign = null;
        Signer m_signerToSign = null;

        public CounterSignature(Key key, CBORObject algorithm = null) : base(key, algorithm)
        {
            context = "CounterSignature";
        }

        public void SetObject(Message msg)
        {
            m_msgToSign = msg;    
        }

        public void SetObject(Signer signer)
        {
            m_signerToSign = signer;
        }

        new public CBORObject EncodeToCBORObject()
        {
            CBORObject cborBodyAttributes = null;
            byte[] rgbBody = null;

            if (m_msgToSign != null) {
                if (m_msgToSign.GetType() == typeof(EnvelopeMessage)) {
                    EnvelopeMessage msg = (EnvelopeMessage) m_msgToSign;
                    msg.Encrypt();
                    CBORObject obj = msg.EncodeToCBORObject();
                    if (obj[1].Type != CBORType.ByteString) throw new Exception("Internal error");
                    if (obj[3].Type != CBORType.ByteString) throw new Exception("Internal error");
                    rgbBody = obj[3].GetByteString();
                    cborBodyAttributes = obj[1];
                }
            }
            else if (m_signerToSign != null) {
               CBORObject obj = m_signerToSign.EncodeToCBORObject();


            }


            return base.EncodeToCBORObject(cborBodyAttributes, rgbBody);
        }
    }
}
