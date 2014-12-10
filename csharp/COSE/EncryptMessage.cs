using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace COSE
{
    public class EncryptMessage : Message
    {
        CBORObject obj;

        protected CBORObject objUnprotected;
        protected CBORObject objProtected;
        byte[] IV;
        List<Recipient> recipientList = new List<Recipient>();
        protected byte[] rgbEncrypted;
        protected byte[] rgbContent;

        public void AddRecipient(Recipient recipient)
        {
            recipientList.Add(recipient);
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

        public void DecodeFromCBORObject(CBORObject obj, int index, int size)
        {
            if (size < 5) throw new Exception("Invalid Encryption structure");

            //  Protected values.
            if (obj[index + 0].Type == CBORType.ByteString) {
                objProtected = CBORObject.DecodeFromBytes(obj[index + 0].GetByteString());
                if (objProtected.Type != CBORType.Map) throw new Exception("Invalid Encryption Structure");
            }
            else if (obj[index + 0].IsNull) {
                objProtected = CBORObject.NewMap();
            }
            else {
                throw new Exception("Invalid Encryption structure");
            }

            //  Unprotected attributes
            if (obj[index + 1].Type == PeterO.Cbor.CBORType.Map) objUnprotected = obj[index + 1];
            else if (obj[index + 1].IsNull) objUnprotected = PeterO.Cbor.CBORObject.NewMap();
            else throw new Exception("Invalid Encryption Structure");

            //  IV
            if (obj[index + 2].Type == CBORType.ByteString) IV = obj[index + 2].GetByteString();
            else if (obj[index + 2].IsNull) ;
            else throw new Exception("Invalid Exception Structure");

            // Cipher Text
            if (obj[index + 3].Type == CBORType.ByteString) rgbEncrypted = obj[index + 3].GetByteString();
            else if (obj[index + 3].IsNull) ; // Detached content - will need to get externally

            // Recipients
            if (obj[index + 4].IsNull) ; // No Recipient structures - this is just fine
            else if (obj[index + 4].Type == CBORType.Array) {
                // An array of recipients to be processed
                for (int i = 0; i < obj[index + 4].Count; i++) {
                    Recipient recip = new Recipient();
                    recip.DecodeFromCBORObject(obj[index + 4][i], 0, obj[index + 4][i].Count);
                    recipientList.Add(recip);
                }
            }
            else {
                //  We are going to assume that this is a single recipient
                Recipient recip = new Recipient();
                recip.DecodeFromCBORObject(obj, index + 4, size - 4);
                recipientList.Add(recip);
            }
        }

        override public byte[] EncodeToBytes()
        {
            CBORObject obj3;

            obj = CBORObject.NewArray();
            obj.Add(1);  // Tag as an encrypt item

            obj3 = EncodeToCBORObject();

            for (int i = 0; i < obj3.Count; i++) obj.Add(obj3[i]);

            return obj.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            CBORObject obj = CBORObject.NewArray();

            if (rgbEncrypted == null) Encrypt();

            if (objProtected != null) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(objProtected);
            obj.Add(objUnprotected); // Add unprotected attributes

            obj.Add(IV);      // Add iv
            obj.Add(rgbEncrypted);      // Add ciphertext

            if (recipientList.Count == 1) {
                CBORObject recipient = recipientList[0].EncodeToCBORObject();

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (recipientList.Count > 1) {
                CBORObject recipients = CBORObject.NewArray();

                foreach (Recipient key in recipientList) {
                    recipients.Add(key.EncodeToCBORObject());
                }
                obj.Add(recipients);
            }
            else {
                obj.Add(null);      // No recipients - set to null
            }
            return obj;
        }





        public virtual void Encrypt()
        {
            string alg;

            //  Get the algorithm we are using - the default is AES GCM

            try {
                alg = objUnprotected["alg"].AsString();
            }
            catch {
                try {
                    alg = objProtected["alg"].AsString();
                }
                catch {
                    alg = "A128GCM";
                    if (objUnprotected == null) objUnprotected = CBORObject.NewMap();
                    objUnprotected.Add("alg", alg);
                }
            }

            byte[] ContentKey = null;

            //  Determine if we are doing a direct encryption
            int recipientTypes = 0;

            foreach (Recipient key in recipientList) {
                switch (key.recipientType) {
                case RecipientType.direct:
                case RecipientType.keyAgreeDirect:
                    if ((recipientTypes & 1) != 0) throw new Exception("It is not legal to have two direct recipients in a message");
                    recipientTypes |= 1;
                    ContentKey = key.GetKey(alg);
                    break;

                default:
                    recipientTypes |= 2;
                    break;
                }
            }

            if (recipientTypes == 3) throw new Exception("It is not legal to mix direct and indirect recipients in a message");

            switch (alg) {
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
                ContentKey = AES(alg, ContentKey);
                break;

            case "A128CBC-HS256":
            case "A192CBC-HS256":
            case "A256CBC-HS256":
                throw new Exception("Content encrption algorithm is not supported");

            default:
                throw new Exception("Content encryption algorithm is not recognized");
            }

 
            foreach (Recipient key in recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt();
            }

            return;
        }

        public void SetContent(byte[] keyBytes)
        {
            rgbContent = keyBytes;
        }

        public void SetContent(string contentString)
        {
            rgbContent = UTF8Encoding.ASCII.GetBytes(contentString);
        }


        private byte[] AES(string alg, byte[] K)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            SecureRandom srng = new SecureRandom();

            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            IV = new byte[96/8];
            srng.NextBytes(IV);

            if (K == null) {
                switch (alg) {
                case "A128GCM":
                    K = new byte[128 / 8];
                    break;

                case "A196GCM":
                    K = new byte[196 / 8];
                    break;

                case "A256GCM":
                    K = new byte[256 / 8];
                    break;

                default:
                    throw new Exception("Unsupported algorithm: " + alg);
                }
                srng.NextBytes(K);
            }

            ContentKey = new KeyParameter(K);
            

            byte[] A = new byte[0];
            if (objProtected != null) {
                A = objProtected.EncodeToBytes();
            }

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbEncrypted = C;

            return K;
        }
    }

    public enum RecipientType
    {
        direct=1, keyAgree=2, keyTransport=3, keyWrap=4, keyAgreeDirect=5, keyTransportAndWrap=6
    }

    public class Recipient : EncryptMessage
    {
        RecipientType m_recipientType;
        Key m_key;

        public Recipient(Key key, string algorithm = null)
        {
            if (algorithm != null) {
                switch (algorithm) {
                case "dir":  // Direct encryption mode
                    if (key.AsString("kty") != "oct") throw new Exception("Invalid parameters");
                    m_recipientType = RecipientType.direct;
                    m_key = key;
                    AddUnprotected("alg", algorithm);
                    break;

                case "ECDH-ES":
                    if (key.AsString("kty") != "EC") throw new Exception("Invalid Parameters");
                    m_recipientType = RecipientType.keyAgreeDirect;
                    m_key = key;
                    AddUnprotected("alg", algorithm);
                    break;

                default:
                    throw new Exception("Unrecognized recipient algorithm");
                }
            }
            else {
                switch (key.AsString("kty")) {
                case "oct":
                    m_recipientType = RecipientType.keyWrap;
                    m_key = key;
                    break;
                }
            }

            if (key.ContainsName("use")) {
                    string usage = key.AsString("use");
                    if (usage != "enc") throw new Exception("Key cannot be used for encrytion");
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
        }

        public Recipient()
        {
        }

        public RecipientType recipientType { get { return m_recipientType; } }

        override public void Encrypt()
        {
            string alg = null;      // Get the algorithm that was set.

            try {
                alg = objProtected["alg"].AsString();
            }
            catch (Exception) {
                try {
                    alg = objUnprotected["alg"].AsString();
                }
                catch (Exception) { }
            }

            if (alg == null) {
                switch (m_key.AsString("kty")) {
                case "oct":
                    switch (m_key.AsBytes("k").Length) {
                    case 128/8:
                        alg = "A128KW";
                        break;

                    case 192/8:
                        alg = "A192KW";
                        break;

                    case 256/8:
                        alg = "A256KW";
                        break;

                    default:
                        throw new Exception("Key size does not match any algorthms");
                    }
                    break;

                case "RSA":
                    alg = "RSA-OAEP-256";
                    break;

                default:
                    throw new Exception("unknown or unsupported key type " + m_key.AsString("kty"));
                }
            }

            switch (alg) {
            case "dir":
            case "ECDH-ES":
                if (m_key.ContainsName("kid")) AddUnprotected("kid", m_key.AsString("kid"));
                break;

            case "A128KW":
            case "A192KW":
            case "A256KW":
                AesWrapEngine foo = new AesWrapEngine();
                KeyParameter parameters = new KeyParameter(m_key.AsBytes("k"));
                foo.Init(true, parameters);
                rgbEncrypted = foo.Wrap(rgbContent, 0, rgbContent.Length);
                AddUnprotected("alg", alg);
                if (m_key.ContainsName("kid")) AddUnprotected("kid", m_key.AsString("kid"));
                break;

            case "RSA-OAEP": {
                    IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha1Digest());
                    RsaKeyParameters pubParameters = new RsaKeyParameters(false, ConvertBigNum(m_key.AsObject("n")), ConvertBigNum(m_key.AsObject("e")));

                    cipher.Init(true, new ParametersWithRandom(pubParameters));

                    byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

                    AddUnprotected("alg", alg);
                    if (m_key.ContainsName("kid")) {
                        AddUnprotected("kid", m_key.AsString("kid"));
                    }
                    rgbEncrypted = outBytes;
                }
                break;

            case "RSA-OAEP-256": {
                    IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest());
                    RsaKeyParameters pubParameters = new RsaKeyParameters(false, ConvertBigNum(m_key.AsObject("n")), ConvertBigNum(m_key.AsObject("e")));

                    cipher.Init(true, new ParametersWithRandom(pubParameters));

                    byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

                    AddUnprotected("alg", alg);
                    if (m_key.ContainsName("kid")) {
                        AddUnprotected("kid", m_key.AsObject("kid"));
                    }
                    rgbEncrypted = outBytes;
                }
                break;

            default:
                throw new Exception("Unknown or unsupported algorithm: " + alg);
            }

        }

        public byte[] GetKey(string alg)
        {
            if (m_key == null) return null;

            try {
                string keyAlgorithm = m_key.AsString("alg");
                if (alg != keyAlgorithm) throw new Exception("Algorithm mismatch between message and key");
            }
            catch(Exception) {}

            //  Figure out how longer the needed key is:

            int cbitKey;
            switch (alg) {
            case "A128GCM":
                cbitKey = 128;
                break;

            case "A192GCM":
                cbitKey = 196;
                break;

            case "A256GCM":
            case "HS256":
                cbitKey = 256;
                break;

            case "HS384":
                cbitKey = 384;
                break;

            case "HS512":
                cbitKey = 512;
                break;

            default:
                throw new Exception("NYI");
            }

            switch (m_key.AsString("kty")) {
            case "oct":
                byte[] rgb =  m_key.AsBytes("k");
                if (rgb.Length * 8 != cbitKey) throw new Exception("Incorrect key size");
                return rgb;

            case "EC":
                {
                    SecureRandom random = new SecureRandom();

                    X9ECParameters p = NistNamedCurves.GetByName(m_key.AsString("crv"));
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);


                    ECKeyPairGenerator pGen = new ECKeyPairGenerator();
                    ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, random);
                    pGen.Init(genParam);

                    Org.BouncyCastle.Math.EC.ECPoint pubPoint = p.Curve.CreatePoint(ConvertBigNum(m_key.AsObject("x")), ConvertBigNum(m_key.AsObject("y")), false);
                    ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);

                    AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

                    IBasicAgreement e1 = new ECDHBasicAgreement();

                    e1.Init(p1.Private);
                    BigInteger k1 = e1.CalculateAgreement(pub);

                    CBORObject epk = CBORObject.NewMap();
                    epk.Add("kty", "EC");
                    epk.Add("crv", m_key.AsString("crv"));
                    ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;
                    epk.Add("x", priv.Q.X.ToBigInteger().ToByteArray());
                    epk.Add("y", priv.Q.Y.ToBigInteger().ToByteArray());
                    AddUnprotected("epk", epk);


                    //  Do the KDF function

                    CBORObject dataArray = CBORObject.NewArray();
                    dataArray.Add(0);
                    dataArray.Add(k1.ToByteArray());

                    string PartyUInfo = null;
                    if (objUnprotected.ContainsKey("PartyUInfo")) PartyUInfo = objUnprotected["PartyUInfo"].AsString();
                    dataArray.Add(PartyUInfo);

                    string PartyVInfo = null;
                    if (objUnprotected.ContainsKey("PartyVInfo")) PartyUInfo = objUnprotected["PartyVInfo"].AsString();
                    dataArray.Add(PartyVInfo);

                    byte[] SubPubInfo = new byte[4];
                    SubPubInfo[3] = (byte) cbitKey;
                    dataArray.Add(SubPubInfo);

                    dataArray.Add(null); // SubPrivInfo

                    byte[] rgbData = dataArray.EncodeToBytes();
                    Sha256Digest sha256 = new Sha256Digest();
                    sha256.BlockUpdate(rgbData, 0, rgbData.Length);
                    byte[] rgbOut = new byte[sha256.GetByteLength()];
                    sha256.DoFinal(rgbOut, 0);

                    byte[] rgbResult = new byte[cbitKey / 8];
                    Array.Copy(rgbOut, rgbResult, rgbResult.Length);

                    return rgbResult;
                }
            }
         
            throw new Exception("NYI");
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
