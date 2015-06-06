using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;

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

        public Org.BouncyCastle.Math.BigInteger AsBigInteger(CBORObject keyName)
        {

            byte[] rgb = m_map[keyName].GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) rgb2[i + 2] = rgb[i];

            return new Org.BouncyCastle.Math.BigInteger(rgb2);
        }

        public CBORObject this[CBORObject name]
        {
            get { return m_map[name]; }
        }

        public byte[] AsBytes(string name)
        {
            return m_map[name].GetByteString();
        }

        public CBORObject AsObject(string name)
        {
            return m_map[name];
        }

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
                case GeneralValuesInt.P521: return NistNamedCurves.GetByName("P-521");
                default:
                    throw new CoseException("Unsupported key type: " + cborKeyType.AsInt32());
                }
            }
            else if (cborCurve.Type == CBORType.TextString) {
                switch (cborCurve.AsString()) {
                case "P-384": return NistNamedCurves.GetByName("P384");
                default:
                throw new CoseException("Unsupported key type: " + cborKeyType.AsString());
                }
            }
            else throw new CoseException("Incorrectly encoded key type");
        }
    }
}
