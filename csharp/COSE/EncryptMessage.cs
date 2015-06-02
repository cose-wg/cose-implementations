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
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

using System.Diagnostics;

namespace COSE
{
    public class EncryptMessage : Message
    {
        CBORObject obj;

        byte[] IV;
        List<Recipient> recipientList = new List<Recipient>();
        protected byte[] rgbEncrypted;
        protected byte[] rgbContent;

        public void AddRecipient(Recipient recipient)
        {
            recipientList.Add(recipient);
        }

        public void DecodeFromCBORObject(CBORObject obj, int index, int size)
        {
#if USE_ARRAY
            if (size < 5) throw new CoseException("Invalid Encryption structure");

            //  Protected values.
            if (obj[index + 0].Type == CBORType.ByteString) {
                objProtected = CBORObject.DecodeFromBytes(obj[index + 0].GetByteString());
                if (objProtected.Type != CBORType.Map) throw new CoseException("Invalid Encryption Structure");
            }
            else if (obj[index + 0].IsNull) {
                objProtected = CBORObject.NewMap();
            }
            else {
                throw new CoseException("Invalid Encryption structure");
            }

            //  Unprotected attributes
            if (obj[index + 1].Type == PeterO.Cbor.CBORType.Map) objUnprotected = obj[index + 1];
            else if (obj[index + 1].IsNull) objUnprotected = PeterO.Cbor.CBORObject.NewMap();
            else throw new CoseException("Invalid Encryption Structure");

            //  IV
            if (obj[index + 2].Type == CBORType.ByteString) IV = obj[index + 2].GetByteString();
            else if (obj[index + 2].IsNull) ;
            else throw new CoseException("Invalid Exception Structure");

            // Cipher Text
            if (obj[index + 3].Type == CBORType.ByteString) rgbEncrypted = obj[index + 3].GetByteString();
            else if (obj[index + 3].IsNull) ; // Detached content - will need to get externally

            // Recipients
            if (obj[index + 4].IsNull && (size == 5)) ; // No Recipient structures - this is just fine
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
#else
            CBORObject tmp;

            //  Protected values.
            tmp = obj[RecordKeys.Protected];
            if (tmp != null) {
                if (tmp.Type == CBORType.ByteString) {
                    objProtected = CBORObject.DecodeFromBytes(tmp.GetByteString());
                    if (objProtected.Type != CBORType.Map) throw new CoseException("Invalid Encryption Structure");
                }
                else {
                    throw new CoseException("Invalid Encryption structure");
                }
            }

            //  Unprotected attributes
            tmp = obj[RecordKeys.Unprotected];
            if (tmp != null) {
                if (tmp.Type == PeterO.Cbor.CBORType.Map) objUnprotected = tmp;
                else throw new CoseException("Invalid Encryption Structure");
            }

            //  IV
            tmp = obj[RecordKeys.IV];
            if (tmp != null) {
                if (tmp.Type == CBORType.ByteString) IV = tmp.GetByteString();
                else throw new CoseException("Invalid Exception Structure");
            }

            // Cipher Text
            tmp = obj[RecordKeys.CipherText];
            if (tmp != null) {
                if (obj[index + 3].Type == CBORType.ByteString) rgbEncrypted = tmp.GetByteString();
            }

            // Recipients
            tmp = obj[RecordKeys.Recipients];
            if (tmp != null) {
                if (tmp.Type == CBORType.Array) {
                    // An array of recipients to be processed
                    for (int i = 0; i < tmp.Count; i++) {
                        Recipient recip = new Recipient();
                        recip.DecodeFromCBORObject(tmp[i], 0, tmp[i].Count);
                        recipientList.Add(recip);
                    }
                }
                else throw new CoseException("Invalid Encryption Structure"); 
            }
#endif
        }

        override public byte[] EncodeToBytes()
        {
            CBORObject obj;

            obj = EncodeToCBORObject();

            return obj.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            CBORObject obj3;

#if USE_ARRAY
            obj = CBORObject.NewArray();
            obj.Add(2);  // Tag as an encrypt item
#else
            obj = CBORObject.NewMap();
            obj.Add(RecordKeys.MsgType, 2);
#endif

            obj3 = Encode();

#if USE_ARRAY
            for (int i = 0; i < obj3.Count; i++) obj.Add(obj3[i]);
#else
            foreach (CBORObject key in obj3.Keys) obj.Add(key, obj3[key]);
#endif
            return obj;
        }

        public virtual CBORObject Encode()
        {
            CBORObject obj;
            
            if (rgbEncrypted == null) Encrypt();

#if USE_ARRAY
            obj = CBORObject.NewArray();

            if (objProtected.Count > 0) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(null);

            obj.Add(objUnprotected); // Add unprotected attributes

            obj.Add(IV);      // Add iv
            obj.Add(rgbEncrypted);      // Add ciphertext
#else
            obj = CBORObject.NewMap();

            if (objProtected.Count > 0) obj.Add(RecordKeys.Protected, objProtected.EncodeToBytes());
            if (objUnprotected.Count > 0) obj.Add(RecordKeys.Unprotected, objUnprotected);
            if ((IV != null) && (IV.Length > 0)) obj.Add(RecordKeys.IV, IV);
            if ((rgbEncrypted != null) && (rgbEncrypted.Length > 0)) obj.Add(RecordKeys.CipherText, rgbEncrypted);
#endif

            if ((recipientList.Count == 1) && !m_forceArray) {
                CBORObject recipient = recipientList[0].Encode();

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (recipientList.Count > 0) {
                CBORObject recipients = CBORObject.NewArray();

                foreach (Recipient key in recipientList) {
                    recipients.Add(key.Encode());
                }
#if USE_ARRAY
                obj.Add(recipients);
#else
                obj.Add(RecordKeys.Recipients, recipients);
#endif
            }
#if USE_ARRAY
            else {
                obj.Add(null);      // No recipients - set to null
            }
#endif
            return obj;
        }

        public virtual void Decrypt(Key key)
        {
            //  Get the CEK
            byte[] CEK = null;
            int cbitCEK = 0;

            CBORObject alg = FindAttribute(HeaderKeys.Algorithm);

            if (alg.Type == CBORType.TextString) {
                throw new CoseException("Algorithm not supported: " + alg.AsString());
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                    cbitCEK = 128;
                    break;

                case AlgorithmValuesInt.AES_GCM_192:
                    cbitCEK = 192;
                    break;

                case AlgorithmValuesInt.AES_GCM_256:
                    cbitCEK = 256;
                    break;

                default:
                    throw new CoseException("Unknown or unimplemented algorithm");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            foreach (Recipient recipient in recipientList) {
                try {
                    CEK = recipient.Decrypt(key, cbitCEK, alg);
                }
                catch (CoseException) { }
            }
            if (CEK == null) {
                //  Generate a random CEK
            }

            if (alg.Type == CBORType.TextString) {
                throw new CoseException("Algorithm not supported " + alg.AsString());
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                case AlgorithmValuesInt.AES_GCM_192:
                case AlgorithmValuesInt.AES_GCM_256:
                    AES_Decrypt(alg, CEK);
                    break;
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

        }

        virtual public void Encrypt()
        {
            CBORObject alg;

            //  Get the algorithm we are using - the default is AES GCM

            try {
                alg = FindAttribute(HeaderKeys.Algorithm);
            }
            catch {
                alg = AlgorithmValues.AES_GCM_128;
                AddUnprotected(HeaderKeys.Algorithm, alg);
            }

            byte[] ContentKey = null;

            //  Determine if we are doing a direct encryption
            int recipientTypes = 0;

            foreach (Recipient key in recipientList) {
                switch (key.recipientType) {
                case RecipientType.direct:
                case RecipientType.keyAgreeDirect:
                    if ((recipientTypes & 1) != 0) throw new CoseException("It is not legal to have two direct recipients in a message");
                    recipientTypes |= 1;
                    ContentKey = key.GetKey(alg);
                    break;

                default:
                    recipientTypes |= 2;
                    break;
                }
            }

            if (recipientTypes == 3) throw new CoseException("It is not legal to mix direct and indirect recipients in a message");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-128-CCM-64":
                    ContentKey = AES_CCM(alg, ContentKey);
                    break;

                case "A128CBC-HS256":
                case "A192CBC-HS256":
                case "A256CBC-HS256":
                    throw new CoseException("Content encryption algorithm is not supported");

                default:
                    throw new CoseException("Content encryption algorithm is not recognized");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                case AlgorithmValuesInt.AES_GCM_192:
                case AlgorithmValuesInt.AES_GCM_256:
                    ContentKey = AES(alg, ContentKey);
                    break;

                default:
                    throw new CoseException("Content encryption algorithm is not recognized");
                }
            }

 
            foreach (Recipient key in recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt();
            }

            return;
        }

        public byte[] GetContent()
        {
            return rgbContent;
        }

        public string GetContentAsString()
        {
            return UTF8Encoding.ASCII.GetChars(rgbContent).ToString();
        }

        public void SetContent(byte[] keyBytes)
        {
            rgbContent = keyBytes;
        }

        public void SetContent(string contentString)
        {
            rgbContent = UTF8Encoding.ASCII.GetBytes(contentString);
        }

        private byte[] AES(CBORObject alg, byte[] K)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            IV = new byte[96/8];
            s_PRNG.NextBytes(IV);

            if (K == null) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                    K = new byte[128 / 8];
                    break;

                case AlgorithmValuesInt.AES_GCM_192:
                    K = new byte[196 / 8];
                    break;

                case AlgorithmValuesInt.AES_GCM_256:
                    K = new byte[256 / 8];
                    break;

                default:
                    throw new CoseException("Unsupported algorithm: " + alg);
                }
                s_PRNG.NextBytes(K);
            }

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed
            
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

        public void AES_Decrypt(CBORObject alg, byte[] K)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            ContentKey = new KeyParameter(K);

            byte[] A = EncodeProtected();

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbContent = C;

        }

        private byte[] AES_CCM(CBORObject alg, byte[] K)
        {
            CcmBlockCipher cipher = new CcmBlockCipher(new AesFastEngine());
            KeyParameter ContentKey;
            int cbitTag = 64;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            IV = new byte[96 / 8];
            s_PRNG.NextBytes(IV);

            if (K == null) {
                Debug.Assert(alg.Type == CBORType.TextString);
                switch (alg.AsString()) {
                case "AES-128-CCM-64":
                    K = new byte[128 / 8];
                    cbitTag = 64;
                    break;

                case "AES-196-CCM-64":
                    K = new byte[196 / 8];
                    cbitTag = 64;
                    break;

                case "AES-256-CCM-64":
                    K = new byte[256 / 8];
                    cbitTag = 64;
                    break;

                default:
                    throw new CoseException("Unsupported algorithm: " + alg);
                }
                s_PRNG.NextBytes(K);
            }

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed

            byte[] A = new byte[0];
            if (objProtected != null) {
                A = objProtected.EncodeToBytes();
            }

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            Array.Resize(ref C, C.Length - (128/8) + (cbitTag/8));
            rgbEncrypted = C;

            return K;
        }
    }

    public enum RecipientType
    {
        direct=1, keyAgree=2, keyTransport=3, keyWrap=4, keyAgreeDirect=5, keyTransportAndWrap=6, password=7
    }

    public class Recipient : EncryptMessage
    {
        RecipientType m_recipientType;
        Key m_key;
        Key m_senderKey;

        public Recipient(Key key, CBORObject algorithm = null)
        {
            if (algorithm != null) {
                if (algorithm.Type == CBORType.TextString) {
                    switch (algorithm.AsString()) {
                    case "dir":  // Direct encryption mode
                        if (key.AsString("kty") != "oct") throw new CoseException("Invalid parameters");
                        m_recipientType = RecipientType.direct;
                        break;

                    case "ECDH-ES":
#if DEBUG
                    case "ECDH-SS":
#endif // DEBUG
                        if (key.AsString("kty") != "EC") throw new CoseException("Invalid Parameters");
                        m_recipientType = RecipientType.keyAgreeDirect;
                        break;

                    case "A128GCMKW":
                    case "A192GCMKW":
                    case "A256GCMKW":
                        if (key.AsString("kty") != "oct") throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyWrap;
                        break;

                    case "ECDH-ES+A128KW":
                    case "ECDH-ES+A192KW":
                    case "ECDH-ES+A256KW":
                        if (key.AsString("kty") != "EC") throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyAgree;
                        break;

                    case "PBES2-HS256+A128KW":
                    case "PBES2-HS256+A192KW":
                    case "PBES-HS256+A256KW":
                        if (key.AsString("kty") != "oct") throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.password;
                        break;

                    default:
                        throw new CoseException("Unrecognized recipient algorithm");
                    }
                }
                else if (algorithm.Type == CBORType.Number) {
                    switch ((AlgorithmValuesInt) algorithm.AsInt32()) {
                    case AlgorithmValuesInt.RSA_OAEP:
                    case AlgorithmValuesInt.RSA_OAEP_256:
                        if (key.AsString("kty") != "RSA") throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyTransport;
                        break;

                    case AlgorithmValuesInt.AES_KW_128:
                    case AlgorithmValuesInt.AES_KW_192:
                    case AlgorithmValuesInt.AES_KW_256:
                        if (key.AsString("kty") != "oct") throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyWrap;
                        break;

                    default:
                        throw new CoseException("Unrecognized recipient algorithm");
                    }
                }
                else throw new CoseException("Algorithm incorrectly encoded");

                m_key = key;
                AddUnprotected(HeaderKeys.Algorithm, algorithm);
            }
            else {
                switch (key.AsString("kty")) {
                case "oct":
                    m_recipientType = RecipientType.keyWrap;
                    switch (key.AsBytes("k").Length) {
                    case 128 / 8:
                        algorithm = AlgorithmValues.AES_KW_128;
                        break;

                    case 192 / 8:
                        algorithm = AlgorithmValues.AES_KW_192;
                        break;

                    case 256 / 8:
                        algorithm = AlgorithmValues.AES_KW_256;
                        break;

                    default:
                        throw new CoseException("Key size does not match any algorthms");
                    }
                    break;

                case "RSA":
                    m_recipientType = RecipientType.keyTransport;
                    algorithm = AlgorithmValues.RSA_OAEP_256;
                    break;

                case "EC":
                    m_recipientType = RecipientType.keyAgree;
                    algorithm = CBORObject.FromObject("ECDH-ES+A128KW");
                    break;
                }
                AddUnprotected(HeaderKeys.Algorithm, CBORObject.FromObject(algorithm));
                m_key = key;
            }

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "enc") throw new CoseException("Key cannot be used for encrytion");
            }

            if (key.ContainsName("key_ops")) {
                CBORObject usageObject = key.AsObject("key_ops");
                bool validUsage = false;

                if (usageObject.Type != CBORType.Array) throw new CoseException("key_ops is incorrectly formed");
                for (int i = 0; i < usageObject.Count; i++) {
                    switch (usageObject[i].AsString()) {
                    case "encrypt":
                    case "keywrap":
                        validUsage = true;
                        break;
                    }
                }
                if (!validUsage) throw new CoseException("Key cannot be used for encryption");
            }

            if (key.ContainsName("kid")) AddUnprotected(HeaderKeys.KeyId, key[CBORObject.FromObject("kid")]);
        }

        public Recipient()
        {
        }

        public RecipientType recipientType { get { return m_recipientType; } }


        public byte[] Decrypt(Key key, int cbitCEK, CBORObject algCEK)
        {
            CBORObject alg = null;
            byte[] rgbSecret;
            byte[] rgbKey;

            try {
                alg = FindAttribute(HeaderKeys.Algorithm);
            }
            catch (CoseException) {
                return null;   // This is a bad state
            }

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "dir":
                    if (key.AsString("kty") != "oct") return null;
                    return key.AsBytes("k");

                case "ECDH-ES":
                    rgbSecret = ECDH_GenerateSecret(key);
                    return KDF(rgbSecret, cbitCEK, algCEK);

                case "A128GCMKW": return AES_GCM_KeyUnwrap(key, 128);
                case "A192GCMKW": return AES_GCM_KeyUnwrap(key, 192);
                case "A256GCMKW": return AES_GCM_KeyUnwrap(key, 256);

                case "PBES2-HS256+A128KW":
                    rgbKey = PBKF2(m_key.AsBytes("k"), FindAttribute("p2s").GetByteString(), FindAttribute("p2c").AsInt32(), 128 / 8, new Sha256Digest());
                    return AES_KeyUnwrap(null, 128, rgbKey);

                case "PBES2-HS256+A192KW":
                    rgbKey = PBKF2(m_key.AsBytes("k"), FindAttribute("p2s").GetByteString(), FindAttribute("p2c").AsInt32(), 192 / 8, new Sha256Digest());
                    return AES_KeyUnwrap(null, 192, rgbKey);

                case "PBES2-HS256+A256KW":
                    rgbKey = PBKF2(m_key.AsBytes("k"), FindAttribute("p2s").GetByteString(), FindAttribute("p2c").AsInt32(), 256 / 8, new Sha256Digest());
                    return AES_KeyUnwrap(null, 256, rgbKey);

                case "ECDH-ES+A128KW":
                    rgbSecret = ECDH_GenerateSecret(key);
                    rgbKey = KDF(rgbSecret, 128, alg);
                    return AES_KeyUnwrap(null, 128, rgbKey);

                case "ECDH-ES+A192KW":
                    rgbSecret = ECDH_GenerateSecret(key);
                    rgbKey = KDF(rgbSecret, 192, alg);
                    return AES_KeyUnwrap(null, 192, rgbKey);

                case "ECDH-ES+A256KW":
                    rgbSecret = ECDH_GenerateSecret(key);
                    rgbKey = KDF(rgbSecret, 256, alg);
                    return AES_KeyUnwrap(null, 256, rgbKey);
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_OAEP: return RSA_OAEP_KeyUnwrap(key, new Sha1Digest());
                case AlgorithmValuesInt.RSA_OAEP_256: return RSA_OAEP_KeyUnwrap(key, new Sha256Digest());

                case AlgorithmValuesInt.AES_KW_128: return AES_KeyUnwrap(key, 128);
                case AlgorithmValuesInt.AES_KW_192: return AES_KeyUnwrap(key, 192);
                case AlgorithmValuesInt.AES_KW_256: return AES_KeyUnwrap(key, 256);

                default:
                    throw new CoseException("Algorithm not supported " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm is incorrectly encoded");

            return null;
        }

        override public void Encrypt()
        {
            CBORObject alg;      // Get the algorithm that was set.
            byte[] rgbSecret;
            byte[] rgbKey;
            CBORObject objSalt;
            CBORObject objIterCount;

            alg = FindAttribute(HeaderKeys.Algorithm);

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "dir":
                case "ECDH-ES":
                case "ECDH-SS":
                    break;

                case "ECDH-ES+A128KW":
                    ECDH_GenerateEphemeral();
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = KDF(rgbSecret, 128, alg);
                    AES_KeyWrap(128, rgbKey);
                    break;

                case "ECDH-ES+A192KW":
                    ECDH_GenerateEphemeral();
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = KDF(rgbSecret, 192, alg);
                    AES_KeyWrap(192, rgbKey);
                    break;

                case "ECDH-ES+A256KW":
                    ECDH_GenerateEphemeral();
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = KDF(rgbSecret, 192, alg);
                    AES_KeyWrap(192, rgbKey);
                    break;

                case "A128GCMKW": AES_GCM_KeyWrap(128); break;
                case "A192GCMKW": AES_GCM_KeyWrap(192); break;
                case "A256GCMKW": AES_GCM_KeyWrap(256); break;

                case "PBES2-HS256+A128KW":
                    objSalt = FindAttribute("p2s");
                    if (objSalt == null) {
                        byte[] salt = new byte[10];
                        s_PRNG.NextBytes(salt);
                        objSalt = CBORObject.FromObject(salt);
                        AddUnprotected("p2s", objSalt);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddUnprotected("p2c", objIterCount);
                    }
                    rgbKey = PBKF2(m_key.AsBytes("k"), objSalt.GetByteString(), objIterCount.AsInt32(), 128 / 8, new Sha256Digest());
                    AES_KeyWrap(128, rgbKey);
                    break;

                case "PBES2-HS384+A192KW":
                    objSalt = FindAttribute("p2s");
                    if (objSalt == null) {
                        byte[] salt = new byte[10];
                        s_PRNG.NextBytes(salt);
                        objSalt = CBORObject.FromObject(salt);
                        AddUnprotected("p2s", objSalt);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddUnprotected("p2c", objIterCount);
                    }
                    rgbKey = PBKF2(m_key.AsBytes("k"), objSalt.GetByteString(), objIterCount.AsInt32(), 192 / 8, new Sha256Digest());
                    AES_KeyWrap(192, rgbKey);
                    break;

                case "PBES2-HS512+256KW":
                    objSalt = FindAttribute("p2s");
                    if (objSalt == null) {
                        byte[] salt = new byte[10];
                        s_PRNG.NextBytes(salt);
                        objSalt = CBORObject.FromObject(salt);
                        AddUnprotected("p2s", objSalt);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddUnprotected("p2c", objIterCount);
                    }
                    rgbKey = PBKF2(m_key.AsBytes("k"), objSalt.GetByteString(), objIterCount.AsInt32(), 256 / 8, new Sha256Digest());
                    AES_KeyWrap(256, rgbKey);
                    break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm: " + alg);
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_OAEP: RSA_OAEP_KeyWrap(new Sha1Digest()); break;
                case AlgorithmValuesInt.RSA_OAEP_256: RSA_OAEP_KeyWrap(new Sha256Digest()); break;

                case AlgorithmValuesInt.AES_KW_128: AES_KeyWrap(128); break;
                case AlgorithmValuesInt.AES_KW_192: AES_KeyWrap(192); break;
                case AlgorithmValuesInt.AES_KW_256: AES_KeyWrap(256); break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm: " + alg);
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");
        }

        public byte[] GetKey(CBORObject alg)
        {
            if (m_key == null) return null;

            try {
                CBORObject keyAlgorithm = m_key[HeaderKeys.Algorithm];
                if ((keyAlgorithm != null) && (alg != keyAlgorithm)) throw new CoseException("Algorithm mismatch between message and key");
            }
            catch(CoseException) {}

            //  Figure out how longer the needed key is:

            int cbitKey;
            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-128-CCM-64":
                    cbitKey = 128;
                    break;

                case "HS384":
                    cbitKey = 384;
                    break;

                default:
                    throw new CoseException("NYI");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                    cbitKey = 128;
                    break;

                case AlgorithmValuesInt.AES_GCM_192:
                    cbitKey = 192;
                    break;

                case AlgorithmValuesInt.AES_GCM_256:
                case AlgorithmValuesInt.HMAC_SHA_256:
                    cbitKey = 256;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_512:
                    cbitKey = 512;
                    break;

                default:
                    throw new CoseException("NYI");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            string algKeyManagement = FindAttribute(HeaderKeys.Algorithm).AsString();

            switch (algKeyManagement) {
            case "dir":
                if (m_key.AsString("kty") != "oct") throw new CoseException("Key and key managment algorithm don't match");
                byte[] rgb =  m_key.AsBytes("k");
                if (rgb.Length * 8 != cbitKey) throw new CoseException("Incorrect key size");
                return rgb;

            case "ECDH-ES":
                {
                    if (m_key.AsString("kty") != "EC") throw new CoseException("Key and key management algorithm don't match");

                    ECDH_GenerateEphemeral();

                    byte[] rgbSecret = ECDH_GenerateSecret(m_key);

                    return KDF(rgbSecret, cbitKey, alg);
                }

            case "ECDH-SS": {
                    if (m_key.AsString("kty") != "EC") throw new CoseException("Key and key managment algorithm don't match");
                    if (FindAttribute("apu") == null) {
                        byte[] rgbAPU = new byte[512 / 8];
                        s_PRNG.NextBytes(rgbAPU);
                        AddUnprotected("apu", CBORObject.FromObject(rgbAPU));
                    }
                    byte[] rgbSecret = ECDH_GenerateSecret(m_key);
                    return KDF(rgbSecret, cbitKey, alg);
                }

            }
         
            throw new CoseException("NYI");
        }

        public void SetSenderKey(COSE.Key senderKey)
        {
            m_senderKey = senderKey;
        }

        public void SetSenderKey(COSE.Key senderKey)
        {
            m_senderKey = senderKey;
        }

        private void AES_KeyWrap(int keySize, byte[] rgbKey = null)
        {
            if (rgbKey == null) {
                if (m_key.AsString("kty") != "oct") throw new CoseException("Key is not correct type");

                rgbKey = m_key.AsBytes("k");
            }
            if (rgbKey.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(true, parameters);
            rgbEncrypted = foo.Wrap(rgbContent, 0, rgbContent.Length);
        }

        private byte[] AES_KeyUnwrap(Key keyObject, int keySize, byte[] rgbKey=null)
        {
            if (keyObject != null) {
                if (keyObject.AsString("kty") != "oct") return null;
                rgbKey = keyObject.AsBytes("k");
            }
            if (rgbKey.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(false, parameters);
            rgbContent = foo.Unwrap(rgbEncrypted, 0, rgbEncrypted.Length);
            return rgbContent;
        }

        private void RSA_OAEP_KeyWrap(IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, m_key.AsBigInteger("n"), m_key.AsBigInteger("e"));

            cipher.Init(true, new ParametersWithRandom(pubParameters, s_PRNG));

            byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

            rgbEncrypted = outBytes;
        }

        private byte[] RSA_OAEP_KeyUnwrap(Key key, IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, key.AsBigInteger("n"), key.AsBigInteger("e"));

            cipher.Init(true, new ParametersWithRandom(pubParameters));

            byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

            return outBytes;

        }

        private void AES_GCM_KeyWrap(int keySize)
        {
            if (m_key.AsString("kty") != "oct") throw new CoseException("Incorrect key type") ;
            byte[] keyBytes = m_key.AsBytes("k");
            if (keyBytes.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            ContentKey = new KeyParameter(keyBytes);
            byte[] A = new byte[0];
            byte[] IV = FindAttribute("iv").GetByteString();
            byte[] tag = FindAttribute("tag").GetByteString();

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, C, len);
            len += cipher.DoFinal(C, len);

            if (len != C.Length) throw new CoseException("NYI");
            rgbEncrypted = C;
            return;

        }

        private byte[] AES_GCM_KeyUnwrap(Key key, int keySize)
        {
            if (key.AsString("kty") != "oct") return null;
            byte[] keyBytes = key.AsBytes("k");
            if (keyBytes.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            ContentKey = new KeyParameter(keyBytes);
            byte[] A = new byte[0];
            byte[] IV = FindAttribute("iv").GetByteString();
            byte[] tag = FindAttribute("tag").GetByteString();

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, C, len);
            len += cipher.DoFinal(C, len);

            if (len != C.Length) throw new CoseException("NYI");
            return C;

        }

        private void ECDH_GenerateEphemeral()
        {
            X9ECParameters p = NistNamedCurves.GetByName(m_key.AsString("crv"));
            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

            ECKeyPairGenerator pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, s_PRNG);
            pGen.Init(genParam);

            AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

            CBORObject epk = CBORObject.NewMap();
            epk.Add("kty", "EC");
            epk.Add("crv", m_key.AsString("crv"));
            ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;
            epk.Add("x", priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
            epk.Add("y", priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned());
            AddUnprotected("epk", epk);
        }

        private byte[] ECDH_GenerateSecret(Key key)
        {
            Key epk;

            if (key.AsString("kty") != "EC") throw new CoseException("Not an EC Key");

            if (m_senderKey != null) {
                epk = m_senderKey;
            }
            else {
                CBORObject epkT = FindAttribute("epk");
                if (epkT == null) throw new CoseException("No Ephemeral key");
                epk = new Key(epkT);
            }

            if (epk.AsString("crv") != key.AsString("crv")) throw new CoseException("not a match of curves");

            //  Get the curve

            X9ECParameters p = NistNamedCurves.GetByName(key.AsString("crv"));
            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

            Org.BouncyCastle.Math.EC.ECPoint pubPoint = p.Curve.CreatePoint(epk.AsBigInteger("x"), epk.AsBigInteger("y"));
            ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);

            ECPrivateKeyParameters priv = new ECPrivateKeyParameters(key.AsBigInteger("d"), parameters);

            IBasicAgreement e1 = new ECDHBasicAgreement();
            e1.Init(priv);

            BigInteger k1 = e1.CalculateAgreement(pub);

            return k1.ToByteArrayUnsigned();
        }

        private byte[] KDF(byte[] secret, int cbitKey, CBORObject algorithmID)
        {
#if USE_OLD_KDF
            //  Build a long byte array
            //  four byte counter
            //  secret
            //  AlgorithmID - [32-bit size || algorithm identifier ]
            //  PartyUInfo - [32-bit size || PartyUInfo ] ---- "apu"
            //  PartyVInfo - [32-bit size || PartyVInfo ] ---- "apv"
            //  SuppPubInfo - 32-bit - key data len
            //  SuppPrivInfo - nothing

            byte[] rgbPartyU = new byte[0];
            byte[] rgbPartyV = new byte[0];
            Debug.Assert(algorithmID.Type == CBORType.TextString);
            byte[] algId = UTF8Encoding.ASCII.GetBytes(algorithmID.AsString());

            CBORObject j = FindAttribute("apu");
            if (j != null) rgbPartyU = j.GetByteString();

            j = FindAttribute("apv");
            if (j != null) rgbPartyV = j.GetByteString();

            int c = 4 + secret.Length + 4 + algId.Length + 4 + rgbPartyU.Length + 4 + rgbPartyV.Length + 4;
            byte[] rgb = new byte[c];

            //  Counter starts at 0

            Array.Copy(secret, 0, rgb, 4, secret.Length);
            c = 4 + secret.Length;

            if (algorithmID.Type == CBORType.TextString) {
                if (algorithmID.AsString().Length > 255) throw new CoseException("Internal error");
                rgb[c + 3] = (byte) algId.Length;
                Array.Copy(algId, 0, rgb, c + 4, algId.Length);
                c += 4 + algorithmID.AsString().Length;
            }
            else throw new CoseException("Unknown encoding for algorithm identifier in KDF function");

            if (rgbPartyU.Length > 255) throw new CoseException("Internal error");
            rgb[c + 3] = (byte) rgbPartyU.Length;
            Array.Copy(rgbPartyU, 0, rgb, c + 4, rgbPartyU.Length);
            c += 4 + rgbPartyU.Length;

            if (rgbPartyV.Length > 255) throw new CoseException("internal error");
            rgb[c + 3] = (byte) rgbPartyV.Length;
            Array.Copy(rgbPartyV, 0, rgb, c + 4, rgbPartyV.Length);
            c += 4 + rgbPartyV.Length;

            if (cbitKey / (256 * 256) != 0) throw new CoseException("internal error");
            rgb[c + 3] = (byte) (cbitKey % 256);
            rgb[c + 2] = (byte) (cbitKey / 256);

            //  Now do iterative hashing

            IDigest digest = new Sha256Digest();
            int cIters = (cbitKey + 255) / 256;
            byte[] rgbDigest = new byte[256 / 8 * cIters];

            for (int i = 0; i < cIters; i++) {
                rgb[3] = (byte) (i + 1);
                digest.Reset();
                digest.BlockUpdate(rgb, 0, rgb.Length);
                digest.DoFinal(rgbDigest, (256 / 8) * i);
            }

            byte[] rgbOut = new byte[cbitKey / 8];
            Array.Copy(rgbDigest, rgbOut, rgbOut.Length);
            return rgbOut;
#else

            //  Do the KDF function
            byte[] rgbIter = new byte[4];

            CBORObject dataArray = CBORObject.NewArray();
            dataArray.Add(algorithmID);

            string PartyUInfo = null;
            if (objUnprotected.ContainsKey("PartyUInfo")) PartyUInfo = objUnprotected["PartyUInfo"].AsString();
            dataArray.Add(PartyUInfo);

            string PartyVInfo = null;
            if (objUnprotected.ContainsKey("PartyVInfo")) PartyVInfo = objUnprotected["PartyVInfo"].AsString();
            dataArray.Add(PartyVInfo);

            byte[] SubPubInfo = new byte[4];
            SubPubInfo[3] = (byte) cbitKey;
            dataArray.Add(SubPubInfo);

            dataArray.Add(null); // SubPrivInfo

            byte[] rgbData = dataArray.EncodeToBytes();
            Sha256Digest sha256 = new Sha256Digest();
            sha256.BlockUpdate(rgbIter, 0, rgbIter.Length);
            sha256.BlockUpdate(secret, 0, rgbIter.Length);
            sha256.BlockUpdate(rgbData, 0, rgbData.Length);
            byte[] rgbOut = new byte[sha256.GetByteLength()];
            sha256.DoFinal(rgbOut, 0);

            byte[] rgbResult = new byte[cbitKey / 8];
            Array.Copy(rgbOut, rgbResult, rgbResult.Length);

            return rgbResult;
#endif
        }

        public static byte[] PBKF2(byte[] password, byte[] salt, int iterCount, int cOctets, IDigest digest)
        {
            //  PRF = HMAC- SHA (256, 384, 512)
            //  P = passsword
            //  S = salt
            //  c = iteration count
            //  dkLen = cbits in octets

            //  l = CIEL(dkLen / hLen)
            //  r = dkLen - (l - 1)*hLen

            // T_n = F ( P, S, c, n)  (iterate n=1 to l)

            // F ( P, S, c, i) = U_1 ^ U_2 ^ ... ^ U_c

            // U_1 = PRF( P, S || INT (i))
            // U_2 = PRF( P, U_1 )
            // U_c = PRF( P, U_{c-1})
            //  INT = int32- big-ending

            HMac hmac = new HMac(digest);
            ICipherParameters K = new KeyParameter(password);
            hmac.Init(K);
            int hLen = hmac.GetMacSize();
            int l = (cOctets + hLen - 1) / hLen;

            byte[] rgbStart = new byte[salt.Length + 4];
            Array.Copy(salt, rgbStart, salt.Length);
            byte[] rgbOutput = new byte[l * hLen];

            for (int i = 1; i <= l; i++) {
                byte[] rgbT = new byte[hLen];
                byte[] rgbH = new byte[hLen];

                hmac.Reset();
                rgbStart[rgbStart.Length - 1] = (byte) i;
                hmac.BlockUpdate(rgbStart, 0, rgbStart.Length);
                hmac.DoFinal(rgbH, 0);
                Array.Copy(rgbH, rgbT, rgbH.Length);

                for (int j = 1; j < iterCount; j++) {
                    hmac.Reset();
                    hmac.BlockUpdate(rgbH, 0, rgbH.Length);
                    hmac.DoFinal(rgbH, 0);
                    for (int k = 0; k < rgbH.Length; k++) rgbT[k] ^= rgbH[k];
                }

                Array.Copy(rgbT, hLen * (i - 1), rgbOutput, 0, rgbT.Length);
            }

            byte[] rgbOut = new Byte[cOctets];
            Array.Copy(rgbOutput, rgbOut, cOctets);
            return rgbOut;
        }
 
    }
}
