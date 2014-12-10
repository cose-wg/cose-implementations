using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

namespace COSE
{
    public abstract class Message
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
}
