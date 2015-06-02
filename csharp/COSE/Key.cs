using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

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

        public void Add(string name, string value)
        {
            m_map.Add(name, value);
        }

        public void Add(string name, byte[] value)
        {
            m_map.Add(name, value);
        }

        public Org.BouncyCastle.Math.BigInteger AsBigInteger(string keyName)
        {

            byte[] rgb = AsBytes(keyName);
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

        public byte[] EncodeToBytes()
        {
            return m_map.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            return m_map;
        }

    }
}
