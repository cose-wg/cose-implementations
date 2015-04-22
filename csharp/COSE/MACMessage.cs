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


namespace COSE
{
    public class MACMessage : Message
    {
        CBORObject obj;

        byte[] rgbTag;
        byte[] rgbContent;


        List<Recipient> recipientList = new List<Recipient>();

        public void AddRecipient(Recipient recipient)
        {
            recipientList.Add(recipient);
        }

        override public byte[] EncodeToBytes()
        {
            CBORObject obj3;

            obj = CBORObject.NewArray();
            obj.Add(3);  // Tag as an MAC item

            obj3 = EncodeToCBORObject();

            for (int i = 0; i < obj3.Count; i++) obj.Add(obj3[i]);

            return obj.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            CBORObject obj = CBORObject.NewArray();

            if (rgbTag == null) MAC();

            if (objProtected.Count > 0)  obj.Add(objProtected.EncodeToBytes());
            else obj.Add(null);

            if (objUnprotected.Count > 0) obj.Add(objUnprotected); // Add unprotected attributes
            else obj.Add(null);

            obj.Add(rgbContent);      // Add ciphertext
            obj.Add(rgbTag);

            if ((!m_forceArray) && (recipientList.Count == 1)) {
                CBORObject recipient = recipientList[0].EncodeToCBORObject();

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (recipientList.Count > 0) {
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

        public void SetContent(byte[] keyBytes)
        {
            rgbContent = keyBytes;
        }

        public void SetContent(string contentString)
        {
            rgbContent = UTF8Encoding.ASCII.GetBytes(contentString);
        }

        protected virtual void MAC()
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
                    alg = "HS256";
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
            case "HS256":
            case "HS384":
            case "HS512":
                ContentKey = HMAC(alg, ContentKey);
                break;

            case "AES-128-MAC-64":
                ContentKey = AES_MAC(alg, ContentKey);
                break;

            default:
                throw new Exception("MAC algorithm is not recognized");
            }


            foreach (Recipient key in recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt();
            }

            return;
        }

        private byte[] BuildContentBytes()
        {
            CBORObject obj = CBORObject.NewArray();

            if (objProtected.Count > 0) obj.Add(objProtected.EncodeToBytes());
            else obj.Add(null);
            obj.Add(rgbContent);

            return obj.EncodeToBytes();
        }

        private byte[] HMAC(string alg, byte[] K)
        {
            int cbitKey;
            IDigest digest;

            switch (alg) {
            case "HS256":
                cbitKey = 256;
                digest = new Sha256Digest();
                break;

            case "HS384":
                cbitKey = 384;
                digest = new Sha384Digest();
                break;
                    
            case "HS512":
                cbitKey=512;
                digest = new Sha512Digest();
                break;

            default:
                throw new Exception("Unrecognized algorithm");
            }

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

        private byte[] AES_MAC(string alg, byte[] K)
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

            switch (alg) {
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

    }
}
