using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;


namespace COSE
{
    public class MACMessage : Message
    {
        CBORObject obj;

        protected CBORObject objUnprotected;
        protected CBORObject objProtected;

        byte[] rgbTag;
        byte[] rgbContent;


        List<Recipient> recipientList = new List<Recipient>();

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

            if (objProtected != null) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(objProtected);
            obj.Add(objUnprotected); // Add unprotected attributes

            obj.Add(rgbContent);      // Add ciphertext
            obj.Add(rgbTag);

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

            default:
                throw new Exception("Content encryption algorithm is not recognized");
            }


            foreach (Recipient key in recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt();
            }

            return;
        }

        private byte[] HMAC(string alg, byte[] K)
        {
            int cbitKey;

                       SecureRandom srng = new SecureRandom();
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
                srng.NextBytes(K);
            }

            HMac hmac = new HMac(digest);
            KeyParameter key = new KeyParameter(K);
            byte[] resBuf = new byte[hmac.GetMacSize()];

            hmac.Init(key);
            hmac.BlockUpdate(rgbContent, 0, 0);
            hmac.DoFinal(resBuf, 0);

            rgbTag = resBuf;

            return K;
        }
    }
}
