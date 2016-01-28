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
    public class Sign0Message : Message
    {
        byte[] rgbContent;

        public Sign0Message()
        {
            m_tag = Tags.Signed0;
        }

        public byte[] BEncodeToBytes()
        {
            CBORObject obj2 = BEncodeToCBORObject();

            return obj2.EncodeToBytes();
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


        public override CBORObject Encode()
        {
            CBORObject obj;

            obj = CBORObject.NewArray();

            if ((objProtected != null) && (objProtected.Count > 0)) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(new byte[0]);

            if ((objUnprotected == null) || (objUnprotected.Count == 0)) obj.Add(CBORObject.NewMap());
            else obj.Add(objUnprotected); // Add unprotected attributes

            obj.Add(rgbContent);

                PerformSignature();

            obj.Add(rgbSignature);
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

        Key keyToSign;
        byte[] rgbSignature = null;
        protected string context = "Signature1";

        public void AddSigner(Key key, CBORObject algorithm = null)
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


        public void PerformSignature()
        {
            CBORObject cborProtected = CBORObject.FromObject(new byte[0]);
            if ((objProtected != null) && (objProtected.Count > 0)) {
                byte[] rgb = objProtected.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }

            if (rgbSignature == null) {
                CBORObject signObj = CBORObject.NewArray();
                signObj.Add(context);
                signObj.Add(cborProtected);
                signObj.Add(externalData); // External AAD
                signObj.Add(rgbContent);

                rgbSignature = Sign(signObj.EncodeToBytes());

#if FOR_EXAMPLES
                m_toBeSigned = signObj.EncodeToBytes();
#endif
            }
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

                case AlgorithmValuesInt.ECDSA_384:
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
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

                default:
                    throw new CoseException("Unknown Algorithm");
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
                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.ECDSA_512:
                    {
                        SecureRandom random = Message.GetPRNG();

                        digest.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        byte[] digestedMessage = new byte[digest.GetDigestSize()];
                        digest.DoFinal(digestedMessage, 0);

                        X9ECParameters p = keyToSign.GetCurve();
                        ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(keyToSign[CoseKeyParameterKeys.EC_D]), parameters);
                        ParametersWithRandom param = new ParametersWithRandom(privKey, random);

                        ECDsaSigner ecdsa = new ECDsaSigner();
                        ecdsa.Init(true, param);

                        BigInteger[] sig = ecdsa.GenerateSignature(digestedMessage);

                        byte[] r = sig[0].ToByteArrayUnsigned();
                        byte[] s = sig[1].ToByteArrayUnsigned();

                        int cbR = (p.Curve.FieldSize + 7) / 8;

                        byte[] sigs = new byte[cbR * 2];
                        Array.Copy(r, 0, sigs, cbR - r.Length, r.Length);
                        Array.Copy(s, 0, sigs, cbR + cbR - s.Length, s.Length);

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

#if FOR_EXAMPLES
        byte[] m_toBeSigned = null;
        public byte[] GetToBeSigned() { return m_toBeSigned; }
#endif
    }
}
