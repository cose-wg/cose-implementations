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

        public void Add(string name, string value)
        {
            m_map.Add(name, value);
        }

        public void Add(string name, byte[] value)
        {
            m_map.Add(name, value);
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
