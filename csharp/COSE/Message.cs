using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Security;

using PeterO.Cbor;

namespace COSE
{
    public class RecordKeys
    {
        static public readonly CBORObject MsgType = CBORObject.FromObject(1);
        static public readonly CBORObject Protected = CBORObject.FromObject(2);
        static public readonly CBORObject Unprotected = CBORObject.FromObject(3);
        static public readonly CBORObject Payload = CBORObject.FromObject(4);
        static public readonly CBORObject Signatures = CBORObject.FromObject(5);
        static public readonly CBORObject Signature = CBORObject.FromObject(6);
        static public readonly CBORObject CipherText = CBORObject.FromObject(4);
        static public readonly CBORObject Recipients = CBORObject.FromObject(9);
        static public readonly CBORObject Tag = CBORObject.FromObject(10);
    };

    public class HeaderKeys
    {
        static public readonly CBORObject Algorithm = CBORObject.FromObject(1);
        static public readonly CBORObject Critical = CBORObject.FromObject(2);
        static public readonly CBORObject ContentType = CBORObject.FromObject(3);
        static public readonly CBORObject EphemeralKey = CBORObject.FromObject(4);
        static public readonly CBORObject KeyId = CBORObject.FromObject(5);
    }

    public enum AlgorithmValuesInt : int
    { 
        AES_GCM_128=1, AES_GCM_192=2, AES_GCM_256=3,
        HMAC_SHA_256=4, HMAC_SHA_384=5, HMAC_SHA_512=6,
        RSA_OAEP = -1, RSA_OAEP_256 = -2,
        AES_KW_128 = -3, AES_KW_192=-4, AES_KW_256=-5,
        DIRECT = -6,
        ECDSA_256 = -7, ECDSA_384=-8, ECDSA_512=-9,
        RSA_PSS_256 = -10, RSA_PSS_512 = -11
        
    }

    public class AlgorithmValues
    {
        static public readonly CBORObject AES_GCM_128 = CBORObject.FromObject(AlgorithmValuesInt.AES_GCM_128);
        static public readonly CBORObject AES_GCM_192 = CBORObject.FromObject(AlgorithmValuesInt.AES_GCM_192);
        static public readonly CBORObject AES_GCM_256 = CBORObject.FromObject(AlgorithmValuesInt.AES_GCM_256);

        static public readonly CBORObject HMAC_SHA_256 = CBORObject.FromObject(AlgorithmValuesInt.HMAC_SHA_256);
        static public readonly CBORObject HMAC_SHA_384 = CBORObject.FromObject(AlgorithmValuesInt.HMAC_SHA_384);
        static public readonly CBORObject HMAC_SHA_512 = CBORObject.FromObject(AlgorithmValuesInt.HMAC_SHA_512);

        static public readonly CBORObject AES_CMAC_128_64 = CBORObject.FromObject("AES-CMAC-128/64");
        static public readonly CBORObject AES_CMAC_256_64 = CBORObject.FromObject("AES-CMAC-256/64");

        static public readonly CBORObject RSA_OAEP = CBORObject.FromObject(AlgorithmValuesInt.RSA_OAEP);
        static public readonly CBORObject RSA_OAEP_256 = CBORObject.FromObject(AlgorithmValuesInt.RSA_OAEP_256);

        static public readonly CBORObject AES_KW_128 = CBORObject.FromObject(AlgorithmValuesInt.AES_KW_128);
        static public readonly CBORObject AES_KW_192 = CBORObject.FromObject(AlgorithmValuesInt.AES_KW_192);
        static public readonly CBORObject AES_KW_256 = CBORObject.FromObject(AlgorithmValuesInt.AES_KW_256);

        static public readonly CBORObject Direct = CBORObject.FromObject(AlgorithmValuesInt.DIRECT);

        static public readonly CBORObject ECDSA_256 = CBORObject.FromObject(AlgorithmValuesInt.ECDSA_256);
        static public readonly CBORObject ECDSA_512 = CBORObject.FromObject(AlgorithmValuesInt.ECDSA_512);

        static public readonly CBORObject RSA_PSS_256 = CBORObject.FromObject(AlgorithmValuesInt.RSA_PSS_256);
        static public readonly CBORObject RSA_PSS_512 = CBORObject.FromObject(AlgorithmValuesInt.RSA_PSS_512);
    }

    public class CoseKeyKeys
    {
        static public readonly CBORObject KeyType = CBORObject.FromObject(1);
        static public readonly CBORObject KeyIdentifier = CBORObject.FromObject(2);
        static public readonly CBORObject Algorithm = CBORObject.FromObject(3);
        static public readonly CBORObject Key_Operations = CBORObject.FromObject("key_ops");
        static public readonly CBORObject x5u = CBORObject.FromObject("x5u");
        static public readonly CBORObject x5c = CBORObject.FromObject("x5c");
        static public readonly CBORObject x5t = CBORObject.FromObject("x5t");
        static public readonly CBORObject x5t_sha_256 = CBORObject.FromObject("x5t#S256");
    }

    public class CoseKeyParameterKeys
    {
        static public readonly CBORObject EC_Curve = CBORObject.FromObject(-1);
        static public readonly CBORObject EC_X = CBORObject.FromObject(-2);
        static public readonly CBORObject EC_Y = CBORObject.FromObject(-3);
        static public readonly CBORObject EC_D = CBORObject.FromObject("d");

        static public readonly CBORObject RSA_e = CBORObject.FromObject(-1);
        static public readonly CBORObject RSA_n = CBORObject.FromObject(-2);

        static public readonly CBORObject IV = CBORObject.FromObject(-1);

        static public readonly CBORObject HKDF_Salt = CBORObject.FromObject(-10);
        static public readonly CBORObject HKDF_Context_PartyU_ID = CBORObject.FromObject(-20);
        static public readonly CBORObject HKDF_Context_PartyU_nonce = CBORObject.FromObject(-21);
        static public readonly CBORObject HKDF_Context_PartyU_Other = CBORObject.FromObject(-22);
        static public readonly CBORObject HKDF_Context_PartyV_ID = CBORObject.FromObject(-23);
        static public readonly CBORObject HKDF_Context_PartyV_nonce = CBORObject.FromObject(-24);
        static public readonly CBORObject HKDF_Context_PartyV_Other = CBORObject.FromObject(-25);
        static public readonly CBORObject HKDF_SuppPub_Other = CBORObject.FromObject("HKDF Supp Public");
        static public readonly CBORObject HKDF_SuppPriv_Other = CBORObject.FromObject("HKDF Supp Private");

    }

    public enum GeneralValuesInt
    {
        KeyType_EC = 1, KeyType_RSA=2, KeyType_Octet = 3,
        P256=4, P521=5,

    }

    public class GeneralValues
    {
        static public readonly CBORObject KeyType_EC = CBORObject.FromObject(GeneralValuesInt.KeyType_EC);
        static public readonly CBORObject KeyType_RSA = CBORObject.FromObject(GeneralValuesInt.KeyType_RSA);
        static public readonly CBORObject KeyType_Octet = CBORObject.FromObject(GeneralValuesInt.KeyType_Octet);
        static public readonly CBORObject P256 = CBORObject.FromObject(GeneralValuesInt.P256);
        static public readonly CBORObject P521 = CBORObject.FromObject(GeneralValuesInt.P521);

    }

    public abstract class Message : Attributes
    {
        protected bool m_forceArray = true;

        protected static SecureRandom s_PRNG = null;

        public static void SetPRNG(SecureRandom prng)
        {
            s_PRNG = prng;
        }

        public static Message DecodeFromBytes(byte[] messageData)
        {
            CBORObject messageObject = CBORObject.DecodeFromBytes(messageData);

            if (messageObject.Type != CBORType.Array) throw new CoseException("Message is not a COSE security message.");

            switch (messageObject[0].AsInt16()) {
            case 1:         // It is an encrytion message
                EncryptMessage enc = new EncryptMessage();

                enc.DecodeFromCBORObject(messageObject, 1, messageObject.Count - 1);
                return enc;

            default:
                throw new CoseException("Message is not recognized as a COSE security message.");
            }
        }

        abstract public byte[] EncodeToBytes();

        public void ForceArray(bool f)
        {
            m_forceArray = f;
        }
    }

    public class Attributes
    {
        protected CBORObject objProtected = CBORObject.NewMap();
        protected CBORObject objUnprotected = CBORObject.NewMap();
        protected CBORObject objDontSend = CBORObject.NewMap();

        public void AddAttribute(string name, string value, bool fProtected)
        {
            if (fProtected) AddProtected(name, value);
            else AddUnprotected(name, value);
        }

        public void AddAttribute(string name, CBORObject value, bool fProtected)
        {
            if (fProtected) AddProtected(name, value);
            else AddUnprotected(name, value);
        }

        public void AddAttribute(CBORObject key, CBORObject value, bool fProtected)
        {
            if (fProtected) AddProtected(key, value);
            else AddUnprotected(key, value);
        }

        public void AddProtected(string label, string value)
        {
            AddProtected(label, CBORObject.FromObject(value)); 
        }

        public void AddProtected(string label, CBORObject value)
        {
            AddProtected(CBORObject.FromObject(label), value);
        }

        public void AddUnprotected(string label, string value)
        {
            AddUnprotected(label, CBORObject.FromObject(label));
        }

        public void AddUnprotected(string label, CBORObject value)
        {
            AddUnprotected(CBORObject.FromObject(label), value);
        }

        public void AddProtected(CBORObject label, CBORObject value)
        {
            RemoveAttribute(label);
            objProtected.Add(label, value);
        }

        public void AddUnprotected(CBORObject label, CBORObject value)
        {
            RemoveAttribute(label);
            objUnprotected.Add(label, value);
        }

        public void AddDontSend(CBORObject label, CBORObject value)
        {
            RemoveAttribute(label);
            objDontSend.Add(label, value);
        }

        public CBORObject FindAttribute(CBORObject label)
        {
            if (objProtected.ContainsKey(label)) return objProtected[label];
            if (objUnprotected.ContainsKey(label)) return objUnprotected[label];
            if (objDontSend.ContainsKey(label)) return objDontSend[label];
            return null;
        }

        public CBORObject FindAttribute(int label)
        {
            return FindAttribute(CBORObject.FromObject(label));
        }

        public CBORObject FindAttribute(string label)
        {
            return FindAttribute(CBORObject.FromObject(label));
        }

        private void RemoveAttribute(CBORObject label)
        {
            if (objProtected.ContainsKey(label)) objProtected.Remove(label);
            if (objUnprotected.ContainsKey(label)) objUnprotected.Remove(label);
            if (objDontSend.ContainsKey(label)) objDontSend.Remove(label);
        }
    }

    public class CoseException : Exception
    {
        public CoseException(string code) : base(code) { }
    }
}
