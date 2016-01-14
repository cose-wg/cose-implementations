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
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace COSE
{
    public class Key
    {
        CBORObject m_map;
 
        public Key()
        {
            m_map = CBORObject.NewMap();
        }

        public Key(CBORObject objKey)
        {
            m_map = objKey;
        }

        public void Add(CBORObject key,CBORObject value)
        {
            m_map.Add(key, value);
        }

        public void Add(string name, string value)
        {
            m_map.Add(name, value);
        }

        public void Add(string name, byte[] value)
        {
            m_map.Add(name, value);
        }

        private bool CompareField(Key key2, CBORObject key)
        {
            if (m_map.ContainsKey(key)) {
                if (!key2.m_map.ContainsKey(key)) return false;
                return m_map[key].CompareTo(key2.m_map[key]) == 0;
            }
            else {
                return !key2.m_map.ContainsKey(key);
            }
        }


        public bool Compare(Key key2)
        {
            if (key2[CoseKeyKeys.KeyType] != m_map[CoseKeyKeys.KeyType]) return false;
            if (!CompareField(key2, CoseKeyKeys.KeyIdentifier)) return false;
            if (!CompareField(key2, CoseKeyKeys.Algorithm)) return false;

            switch ((GeneralValuesInt) m_map[CoseKeyKeys.KeyType].AsInt32()) {
            case GeneralValuesInt.KeyType_RSA:
                if (!CompareField(key2, CoseKeyParameterKeys.RSA_e) ||
                    !CompareField(key2, CoseKeyParameterKeys.RSA_n)) {
                    return false;
                }
                break;

            case GeneralValuesInt.KeyType_EC2:
                if (!CompareField(key2, CoseKeyParameterKeys.EC_Curve) ||
                    !CompareField(key2, CoseKeyParameterKeys.EC_X) ||
                    !CompareField(key2, CoseKeyParameterKeys.EC_Y)) {
                    return false;
                }
                break;

            case GeneralValuesInt.KeyType_Octet:
                if (!CompareField(key2, CoseKeyParameterKeys.Octet_k)) return false;
                break;

            default:
                return true;
            }
                        return true;
        }

        public Org.BouncyCastle.Math.BigInteger AsBigInteger(CBORObject keyName)
        {

            byte[] rgb = m_map[keyName].GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) rgb2[i + 2] = rgb[i];

            return new Org.BouncyCastle.Math.BigInteger(rgb2);
        }

        public CBORObject AsCBOR()
        {
            return m_map;
        }

        public CBORObject this[CBORObject name]
        {
            get { return m_map[name]; }
        }

        public byte[] AsBytes(CBORObject name)
        {
            return m_map[name].GetByteString();
        }

#if false
        public CBORObject AsObject(string name)
        {
            return m_map[name];
        }
#endif

        public string AsString(string name)
        {
            return m_map[name].AsString();
        }

        public Boolean ContainsName(string name)
        {
            return m_map.ContainsKey(name);
        }

        public Boolean ContainsName(CBORObject key)
        {
            return m_map.ContainsKey(key);
        }

        public byte[] EncodeToBytes()
        {
            return m_map.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            return m_map;
        }

        public X9ECParameters GetCurve()
        {
            CBORObject cborKeyType = m_map[CoseKeyKeys.KeyType];

            if (cborKeyType == null) throw new CoseException("Malformed key struture");
            if ((cborKeyType.Type != CBORType.Number) && (cborKeyType != GeneralValues.KeyType_EC)) throw new CoseException("Not an EC key");

            CBORObject cborCurve = m_map[CoseKeyParameterKeys.EC_Curve];
            if (cborCurve.Type == CBORType.Number) {
                switch ((GeneralValuesInt) cborCurve.AsInt32()) {
                case GeneralValuesInt.P256: return NistNamedCurves.GetByName("P-256");
                case GeneralValuesInt.P384: return NistNamedCurves.GetByName("P-384");
                case GeneralValuesInt.P521: return NistNamedCurves.GetByName("P-521");
                default:
                    throw new CoseException("Unsupported key type: " + cborKeyType.AsInt32());
                }
            }
            else if (cborCurve.Type == CBORType.TextString) {
                switch (cborCurve.AsString()) {
                default:
                throw new CoseException("Unsupported key type: " + cborKeyType.AsString());
                }
            }
            else throw new CoseException("Incorrectly encoded key type");
        }

        public Key PublicKey()
        {
            Key newKey = new Key();
            switch ((GeneralValuesInt) m_map[CoseKeyKeys.KeyType].AsInt16()) {
            case GeneralValuesInt.KeyType_Octet:
                return null;

            case GeneralValuesInt.KeyType_RSA:
                newKey.Add(CoseKeyParameterKeys.RSA_n, m_map[CoseKeyParameterKeys.RSA_n]);
                newKey.Add(CoseKeyParameterKeys.RSA_e, m_map[CoseKeyParameterKeys.RSA_e]);
                break;

            case GeneralValuesInt.KeyType_EC2:
                newKey.Add(CoseKeyParameterKeys.EC_Curve, m_map[CoseKeyParameterKeys.EC_Curve]);
                newKey.Add(CoseKeyParameterKeys.EC_X, m_map[CoseKeyParameterKeys.EC_X]);
                newKey.Add(CoseKeyParameterKeys.EC_Y, m_map[CoseKeyParameterKeys.EC_Y]);
                break;

            default:
                return null;
            }

            foreach (CBORObject obj in m_map.Keys) {
                switch (obj.Type) {
                case CBORType.Number:
                    if (obj.AsInt32() > 0) {
                        newKey.Add(obj, m_map[obj]);
                    }
                    break;

                case CBORType.TextString:
                    newKey.Add(obj, m_map[obj]);
                    break;

                }
            }
                return newKey;
        }

        public static void NewKey()
        {
            X9ECParameters p = NistNamedCurves.GetByName("P-384");

            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

            ECKeyPairGenerator pGen = new ECKeyPairGenerator();
           ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, new Org.BouncyCastle.Security.SecureRandom());
            pGen.Init(genParam);

            AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

            CBORObject epk = CBORObject.NewMap();
            epk.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_EC);
            epk.Add(CoseKeyParameterKeys.EC_Curve, "P-384");
            ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;
            epk.Add(CoseKeyParameterKeys.EC_X, priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
            epk.Add(CoseKeyParameterKeys.EC_Y, priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned());
            epk.Add(CoseKeyParameterKeys.EC_D, ((ECPrivateKeyParameters) p1.Private).D.ToByteArrayUnsigned());

            string xxx = epk.ToJSONString();
        }
    }

    public class KeySet
    {
        List<Key> m_keyList = new List<Key>();

        public void AddKey(Key key)
        {
            foreach (Key k in m_keyList) {
                if (key.Compare(k)) return;
            }
            m_keyList.Add(key);
        }

        public byte[] EncodeToBytes()
        {
            CBORObject m_array = CBORObject.NewArray();

            foreach (Key k in m_keyList) {
                m_array.Add(k.AsCBOR());
            }

            return m_array.EncodeToBytes();
        }
    }
}
