using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

namespace COSE
{
    public abstract class Message : Attributes
    {
        public static Message DecodeFromBytes(byte[] messageData)
        {
            CBORObject messageObject = CBORObject.DecodeFromBytes(messageData);

            if (messageObject.Type != CBORType.Array) throw new Exception("Message is not a COSE security message.");

            switch (messageObject[0].AsInt16()) {
            case 1:         // It is an encrytion message
                EncryptMessage enc = new EncryptMessage();

                enc.DecodeFromCBORObject(messageObject, 1, messageObject.Count - 1);
                return enc;

            default:
                throw new Exception("Message is not recognized as a COSE security message.");
            }
        }

        abstract public byte[] EncodeToBytes();
    }

    public class Attributes
    {
        protected CBORObject objProtected = CBORObject.NewMap();
        protected CBORObject objUnprotected = CBORObject.NewMap();

        public void AddProtected(string name, string value)
        {
            AddProtected(name, CBORObject.FromObject(value)); 
        }

        public void AddProtected(string name, CBORObject value)
        {
            if (objUnprotected.ContainsKey(name)) objUnprotected.Remove(CBORObject.FromObject(name));
            if (objProtected.ContainsKey(name)) objProtected[name] = value;
            else objProtected.Add(name, value);
        }

        public void AddUnprotected(string name, string value)
        {
            AddUnprotected(name, CBORObject.FromObject(value));
        }

        public void AddUnprotected(string name, CBORObject value)
        {
            if (objProtected.ContainsKey(name)) objProtected.Remove(CBORObject.FromObject(name));
            if (objUnprotected.ContainsKey(name)) objUnprotected[name] = value;
            else objUnprotected.Add(name, value);
        }
 
        public byte[] EncodeProtected()
        {
            byte[] A = new byte[0];
            if (objProtected != null) A = objProtected.EncodeToBytes();
            return A;
        }

        public CBORObject FindAttribute(string name)
        {
            if (objProtected.ContainsKey(name)) return objProtected[name];
            if (objUnprotected.ContainsKey(name)) return objUnprotected[name];
            return null;
        }
    }
}
