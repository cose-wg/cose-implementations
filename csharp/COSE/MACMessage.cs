using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

using System.Diagnostics;

namespace COSE
{

    public class MAC0Message : MACMessage
    {
        public MAC0Message()
        {
            strContext = "MAC0";
            m_tag = Tags.MAC0;
        }

        public override void AddRecipient(Recipient recipient)
        {
            if (recipientList.Count != 0) throw new Exception("Can't have more than one recipient");
            if (recipient.recipientType != RecipientType.direct) throw new Exception("Must be direct recipient");

            recipient.SetContext("Mac0_Recipient");
            recipientList.Add(recipient);
        }

        public override CBORObject Encode()
        {
            CBORObject obj;

            if (rgbTag == null) MAC();

            obj = CBORObject.NewArray();

            if (objProtected.Count > 0) obj.Add(objProtected.EncodeToBytes());
            else obj.Add(new byte[0]);

            if (objUnprotected.Count > 0) obj.Add(objUnprotected); // Add unprotected attributes
            else obj.Add(CBORObject.NewMap());

            obj.Add(rgbContent);      // Add ciphertext
            obj.Add(rgbTag);

            return obj;
        }

    }

    public class MACMessage : Message
    {
        protected byte[] rgbTag;
        protected byte[] rgbContent;
        byte[] external_aad = null;
        protected string strContext = "MAC";

        public MACMessage()
        {
            m_tag = Tags.MAC;
        }

        protected List<Recipient> recipientList = new List<Recipient>();
        public List<Recipient> RecipientList { get { return recipientList; } }

        public virtual void AddRecipient(Recipient recipient)
        {
            recipient.SetContext("Mac_Recipient");
            recipientList.Add(recipient);
        }

 
        public override CBORObject Encode()
        {
            CBORObject obj;
            
            if (rgbTag == null) MAC();

#if USE_ARRAY
            obj = CBORObject.NewArray();

            if (objProtected.Count > 0) obj.Add(objProtected.EncodeToBytes());
            else obj.Add(new byte[0]);

            if (objUnprotected.Count > 0) obj.Add(objUnprotected); // Add unprotected attributes
            else obj.Add(CBORObject.NewMap());

            obj.Add(rgbContent);      // Add ciphertext
            obj.Add(rgbTag);

            if ((!m_forceArray) && (recipientList.Count == 1)) {
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
                obj.Add(recipients);
            }
            else {
                obj.Add(null);      // No recipients - set to null
            }
#else
            obj = CBORObject.NewMap();

            if (objProtected.Count > 0) obj.Add(RecordKeys.Protected, objProtected.EncodeToBytes());

            if (objUnprotected.Count > 0) obj.Add(RecordKeys.Unprotected, objUnprotected); // Add unprotected attributes

            obj.Add(RecordKeys.CipherText,  rgbContent);      // Add ciphertext
            obj.Add(RecordKeys.Tag, rgbTag);

            if (recipientList.Count > 0) {
                CBORObject recipients = CBORObject.NewArray();

                foreach (Recipient key in recipientList) {
                    recipients.Add(key.Encode());
                }
                obj.Add(RecordKeys.Recipients, recipients);
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

        public void SetExternalAAD(byte[] bytes)
        {
            external_aad = bytes;
        }

        public  virtual void MAC()
        {
            CBORObject alg;

            //  Get the algorithm we are using - the default is AES GCM

            alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) {
                alg = AlgorithmValues.HMAC_SHA_256;
                if (objUnprotected == null) objUnprotected = CBORObject.NewMap();
                objUnprotected.Add(HeaderKeys.Algorithm, alg);

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

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-128-MAC-64":
                    ContentKey = AES_MAC(alg, ContentKey);
                    break;

                case "AES-CMAC-128/64":
                case "AES-CMAC-256/64":
                    ContentKey = AES_CMAC(alg, ContentKey);
                    break;

                default:
                    throw new Exception("MAC algorithm is not recognized");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256:
                case AlgorithmValuesInt.HMAC_SHA_384:
                case AlgorithmValuesInt.HMAC_SHA_512:
                    ContentKey = HMAC(alg, ContentKey);
                    break;

                default:
                    throw new Exception("MAC algorithm not recognized" + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");


            foreach (Recipient key in recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt();
            }

#if FOR_EXAMPLES
            m_cek = ContentKey;
#endif

            return;
        }

        public byte[] BuildContentBytes()
        {
            CBORObject obj = CBORObject.NewArray();

            obj.Add(strContext);
            if (objProtected.Count > 0) obj.Add(objProtected.EncodeToBytes());
            else obj.Add(CBORObject.FromObject(new byte[0]));
            if (external_aad != null) obj.Add(CBORObject.FromObject(external_aad));
            else obj.Add(CBORObject.FromObject(new byte[0]));
            obj.Add(rgbContent);

            return obj.EncodeToBytes();
        }

        private byte[] HMAC(CBORObject alg, byte[] K)
        {
            int cbitKey;
            IDigest digest;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                default:
                    throw new Exception("Unrecognized algorithm");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256:
                    cbitKey = 256;
                    digest = new Sha256Digest();
                    break;

                case AlgorithmValuesInt.HMAC_SHA_384:
                    cbitKey = 384;
                    digest = new Sha384Digest();
                    break;

                case AlgorithmValuesInt.HMAC_SHA_512:
                    cbitKey = 512;
                    digest = new Sha512Digest();
                    break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            if (K == null) {
                K = new byte[cbitKey/8];
                s_PRNG.NextBytes(K);
            }

            HMac hmac = new HMac(digest);
            KeyParameter key = new KeyParameter(K);
            byte[] resBuf = new byte[hmac.GetMacSize()];

            byte[] toDigest = BuildContentBytes();

            hmac.Init(key);
            hmac.BlockUpdate(toDigest, 0, toDigest.Length);
            hmac.DoFinal(resBuf, 0);

            rgbTag = resBuf;

            return K;
        }

        private byte[] AES_CMAC(CBORObject alg, byte[] K)
        {
            int cbitKey;
            int cbitTag;
            //  Defaults to PKCS#7

            IBlockCipher aes = new AesFastEngine();
            CMac mac = new CMac(aes);

            KeyParameter ContentKey;

            //  The requirements from spec
            //  IV is 128 bits of zeros
            //  key sizes are 128, 192 and 256 bits
            //  Authentication tag sizes are 64 and 128 bits

            byte[] IV = new byte[128 / 8];

            Debug.Assert(alg.Type == CBORType.TextString);
            switch (alg.AsString()) {
            case "AES-128-MAC-64":
                cbitKey = 128;
                cbitTag = 64;
                break;

            case "AES-CMAC-256/64":
                cbitKey = 256;
                cbitTag = 64;
                break;

            default:
                throw new Exception("Unrecognized algorithm");
            }

            if (K == null) {
                K = new byte[cbitKey / 8];
                s_PRNG.NextBytes(K);
            }

            ContentKey = new KeyParameter(K);

            //  Build the text to be digested

            mac.Init(ContentKey);

            byte[] toDigest = BuildContentBytes();

            byte[] C = new byte[128/8];
            mac.BlockUpdate(toDigest, 0, toDigest.Length);
            mac.DoFinal(C, 0);

            rgbTag = new byte[cbitTag / 8];
            Array.Copy(C, 0, rgbTag, 0, cbitTag / 8);

            return K;
        }

        private byte[] AES_MAC(CBORObject alg, byte[] K)
        {
            int cbitKey;
            int cbitTag;
            //  Defaults to PKCS#7
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()));
 
            KeyParameter ContentKey;

            //  The requirements from spec
            //  IV is 128 bits of zeros
            //  key sizes are 128, 192 and 256 bits
            //  Authentication tag sizes are 64 and 128 bits

            byte[] IV = new byte[128/8];

            Debug.Assert(alg.Type == CBORType.TextString);
            switch (alg.AsString()) {
            case "AES-128-MAC-64":
                cbitKey = 128;
                cbitTag = 64;
                break;

            default:
                throw new Exception("Unrecognized algorithm");
            }

            if (K == null) {
                K = new byte[cbitKey / 8];
                s_PRNG.NextBytes(K);
            }

            ContentKey = new KeyParameter(K);

            //  Build the text to be digested

            ParametersWithIV parameters = new ParametersWithIV(ContentKey, IV);

            cipher.Init(true, parameters);

            byte[] toDigest = BuildContentBytes();

            byte[] C = new byte[toDigest.Length + 128/8];
            int len = cipher.ProcessBytes(toDigest, 0, toDigest.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbTag = new byte[cbitTag / 8];
            Array.Copy(C, len - 128 / 8, rgbTag, 0, cbitTag / 8);

            return K;
        }

#if FOR_EXAMPLES
        byte[] m_cek= null;
        public byte[] getCEK() { return m_cek; }
#endif
    }
}
