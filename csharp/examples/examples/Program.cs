using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

using PeterO.Cbor;
using JOSE;

namespace examples
{


    class Program
    {
        enum Outputs { cbor = 1, cborDiag = 2, jose = 3, jose_compact = 4, jose_flatten = 5 };

        static Outputs[] RgOutputs = new Outputs[] { Outputs.cborDiag  /*, Outputs.cbor, Outputs.cborFlatten*/ };

        static void Main(string[] args)
        {
            RunTestsInDirectory("c:\\Projects\\COSE\\examples\\spec-examples");
        }

        static void RunTestsInDirectory(string strDirectory)
        {
            DirectoryInfo diTop;

            diTop = new DirectoryInfo(strDirectory);
            foreach (var di in diTop.EnumerateDirectories()) {
                if ((!di.Attributes.HasFlag(FileAttributes.Hidden)) &&
                    (di.FullName.Substring(di.FullName.Length-4) != "\\new")) {
                    RunTestsInDirectory(di.FullName);
                }
            }

            foreach (var di in diTop.EnumerateFiles()) {
                if (di.Extension == ".json") {
                    ProcessFile(di);
                }
            }
        }

        static void ProcessFile(FileInfo di)
        {
            StreamReader file = File.OpenText(di.FullName);
            string fileText = file.ReadToEnd();
            JSON control = JSON.Parse(fileText);
            file.Close();

            try {
                if (ProcessJSON(control)) {
                    fileText = control.Serialize();
                    if (!Directory.Exists(di.DirectoryName + "\\new")) Directory.CreateDirectory(di.DirectoryName + "\\new");
                    StreamWriter file2 = File.CreateText(di.DirectoryName + "\\new\\" + di.Name);
                    file2.Write(fileText);
                    file2.Write("\r\n");
                    file2.Close();
                }
            }
            catch (Exception e) {
                Console.WriteLine("ERROR: " + e.ToString());
            }
        }

        static bool ProcessJSON(JSON control)
        {
            bool modified = false;
            StaticPrng prng = new StaticPrng();

            if (control.ContainsKey("title")) {
                Console.WriteLine("Processing: " + control["title"].AsString());
            }
            if (control.ContainsKey("description")) {
                Console.WriteLine("Description: " + control["description"].AsString());
            }

            if (control["input"].ContainsKey("rng_stream")) {
                if (control["input"]["rng_stream"].nodeType == JsonType.text) {
                    prng.AddSeedMaterial(FromHex(control["input"]["rng_stream"].AsString()));
                }
                else if (control["input"]["rng_stream"].nodeType == JsonType.array) {
                    foreach (var x in control["input"]["rng_stream"].array) {
                        prng.AddSeedMaterial(FromHex(x.AsString()));
                    }
                }
            }
            COSE.Message.SetPRNG(prng);
            JOSE.Message.SetPRNG(prng);

            foreach (Outputs output in RgOutputs) {
                string outputName;
                switch (output) {
                case Outputs.cbor: outputName = "cbor"; break;
                case Outputs.cborDiag: outputName = "cbor_diag"; break;
                case Outputs.jose: outputName = "json"; break;
                case Outputs.jose_flatten: outputName = "json_flat"; break;
                case Outputs.jose_compact: outputName = "compact"; break;
                default: throw new Exception("unknown output type");
                }

                prng.Reset();

                try {
                    byte[] result;

                    if (control["input"].ContainsKey("mac")) result = ProcessMAC(output, control);
                    else if (control["input"].ContainsKey("encrypt")) result = ProcessEncrypt(output, control);
                    else if (control["input"].ContainsKey("sign")) result = ProcessSign(output, control);
                    else throw new Exception("Unknown operation in control");

                    if (control["output"].ContainsKey(outputName)) {
                        if (output == Outputs.cbor) {
 
                            byte[] rgbSource = FromHex(control["output"][outputName].AsString());
                            if (!rgbSource.SequenceEqual(result)) {
                                Console.WriteLine();
                                Console.WriteLine("******************* New and Old do not match!!!");
                                Console.WriteLine();


                                control["output"][outputName].Set(ToHex(result));
                                modified = true;
                            }
                        }
                        else if (output == Outputs.cborDiag) {
                            string strSource = control["output"][outputName].ToString();
                            string strThis = UTF8Encoding.UTF8.GetString(result);

                            if (strSource != strThis) {
                                Console.WriteLine();
                                Console.WriteLine("******************* New and Old do not match!!!");
                                Console.WriteLine();

                                control["output"][outputName].Set(strThis);
                                modified = true;
                            }
                        }
 
                        else {
                            string strSource = control["output"][outputName].ToString();
                            string strThis = UTF8Encoding.UTF8.GetString(result);

                            if (strSource != strThis) {
                                Console.WriteLine();
                                Console.WriteLine("******************* New and Old do not match!!!");
                                Console.WriteLine();


                                if (output == Outputs.jose_compact) control["output"][outputName].Set(strThis);
                                else control["output"][outputName].Set(JSON.Parse(strThis));
                                modified = true;
                            }
                        }
                    }
                    else {
                        switch (output) {
                        case Outputs.cbor:
                        case Outputs.jose_compact:
                            control["output"].Add(outputName, ToHex(result));
                            break;

                        case Outputs.cborDiag:
                            control["output"].Add(outputName, UTF8Encoding.UTF8.GetString(result));
                            break;

                        case Outputs.jose:
                        case Outputs.jose_flatten:
                            control["output"].Add(outputName, JSON.Parse(UTF8Encoding.UTF8.GetString(result)));
                            break;
                        }
                        modified = true;
                    }

                    if (prng.IsDirty) {
                        if (control["input"].ContainsKey("rng_stream")) control["input"]["rng_stream"].Set(ToHex(prng.buffer));
                        else control["input"].Add("rng_stream", ToHex(prng.buffer));
                        modified = true;
                    }
                }
                catch (BadOutputException) {
                    if (control["output"].ContainsKey(outputName)) Console.WriteLine(String.Format("Output contains '{0}', but this format is not legal for the configuration", outputName));
                }
                catch (COSE.CoseException e) {
                    Console.WriteLine(String.Format("COSE threw an error '{0}'.", e.ToString()));
                }
                catch (JOSE.JOSE_Exception e) {
                    Console.WriteLine(String.Format("COSE threw an error '{0}'.", e.ToString()));
                }
            }

            return modified;
        }

        static byte[] ProcessSign(Outputs outputFormat, JSON control)
        {
            if (outputFormat < Outputs.jose) {
                COSE.SignMessage msg = new COSE.SignMessage();

                JSON input = control["input"];
                JSON sign = input["sign"];

                msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], true);
                if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], false);

                if ((!sign.ContainsKey("signers")) || (sign["signers"].nodeType != JsonType.array)) throw new Exception("Missing or malformed recipients");
                foreach (JSON recip in sign["signers"].array) {
                    msg.AddSigner(GetSigner(recip));
                }

                if (outputFormat == Outputs.cborDiag) return UTF8Encoding.UTF8.GetBytes(msg.EncodeToCBORObject().ToString());
                return msg.EncodeToBytes();
            }
            else {
                JOSE.SignMessage msg = new JOSE.SignMessage();

                JSON input = control["input"];
                JSON sign = input["sign"];

                if (outputFormat != Outputs.jose_flatten) msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], true);
                if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], false);

                if ((!sign.ContainsKey("signers")) || (sign["signers"].nodeType != JsonType.array)) throw new Exception("Missing or malformed recipients");
                if ((sign["signers"].Count > 1) && (outputFormat == Outputs.jose_flatten)) throw new BadOutputException();
                foreach (JSON recip in sign["signers"].array) {
                    msg.AddSigner(GetSignerJOSE(recip));
                }

                if (outputFormat == Outputs.jose_compact) return UTF8Encoding.UTF8.GetBytes(msg.EncodeCompact());
                return UTF8Encoding.UTF8.GetBytes(msg.Encode());
            }
        }

        static byte[] ProcessEncrypt(Outputs outputFormat, JSON control)
        {
            JSON input = control["input"];
            JSON encrypt = input["encrypt"];

            if (outputFormat < Outputs.jose) {
                COSE.EncryptMessage msg = new COSE.EncryptMessage();

                msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (encrypt.ContainsKey("protected")) AddAttributes(msg, encrypt["protected"], true);
                if (encrypt.ContainsKey("unprotected")) AddAttributes(msg, encrypt["unprotected"], false);

                if (!encrypt.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].nodeType != JsonType.array)) throw new Exception("Missing or malformed recipients");
                foreach (JSON recip in encrypt["recipients"].array) {
                    msg.AddRecipient(GetRecipient(recip));
                }

                if (outputFormat == Outputs.cborDiag)     return UTF8Encoding.UTF8.GetBytes( msg.EncodeToCBORObject().ToString());
                return msg.EncodeToBytes();
            }
            else {
                JOSE.EncryptMessage msg = new JOSE.EncryptMessage();

                if (outputFormat != Outputs.jose_flatten) msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (encrypt.ContainsKey("aad")) msg.SetAAD(encrypt["aad"].AsString());

                if (encrypt.ContainsKey("protected_jose")) AddAttributes(msg, encrypt["protected_jose"], true);
                if (encrypt.ContainsKey("unprotected_jose")) AddAttributes(msg, encrypt["unprotected_jose"], false);

                if (!encrypt.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].nodeType != JsonType.array)) throw new Exception("Missing or malformed recipients");
                if ((encrypt["recipients"].Count > 1) && (outputFormat != Outputs.jose)) throw new BadOutputException();

                foreach (JSON recip in encrypt["recipients"].array) {
                    msg.AddRecipient(GetRecipientJOSE(recip));
                }

                if (outputFormat == Outputs.jose_compact) return UTF8Encoding.UTF8.GetBytes(msg.EncodeCompact());
                return UTF8Encoding.UTF8.GetBytes( msg.Encode());

            }
        }

        static byte[] ProcessMAC(Outputs outputFormat, JSON control)
        {
            if (outputFormat < Outputs.jose) {
                COSE.MACMessage msg = new COSE.MACMessage();

                msg.ForceArray(true);

                JSON input = control["input"];

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                JSON mac = input["mac"];

                if (mac.ContainsKey("protected")) AddAttributes(msg, mac["protected"], true);
                if (mac.ContainsKey("unprotected")) AddAttributes(msg, mac["unprotected"], false);

                if (!mac.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!mac.ContainsKey("recipients")) || (mac["recipients"].nodeType != JsonType.array)) throw new Exception("Missing or malformed recipients");
                if ((mac["recipients"].Count > 1) && (outputFormat == Outputs.jose_flatten)) throw new BadOutputException();

                foreach (JSON recip in mac["recipients"].array) {
                    msg.AddRecipient(GetRecipient(recip));
                }

                if (outputFormat == Outputs.cborDiag) return UTF8Encoding.UTF8.GetBytes(msg.EncodeToCBORObject().ToString());
                return msg.EncodeToBytes();
            }
            else {
                JOSE.SignMessage msg = new JOSE.SignMessage();

                JSON input = control["input"];
                JSON sign = input["mac"];

                if (outputFormat != Outputs.jose_flatten) msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (sign.ContainsKey("protected_jose")) AddAttributes(msg, sign["protected_jose"], true);
                if (sign.ContainsKey("unprotected_jose")) AddAttributes(msg, sign["unprotected_jose"], false);

                if (!sign.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!sign.ContainsKey("recipients")) || (sign["recipients"].nodeType != JsonType.array)) throw new Exception("Missing or malformed recipients");
                foreach (JSON recip in sign["recipients"].array) {
                    msg.AddSigner(GetSignerJOSE(recip));
                }

                if (outputFormat == Outputs.jose_compact) return UTF8Encoding.UTF8.GetBytes(msg.EncodeCompact());
                return UTF8Encoding.UTF8.GetBytes(msg.Encode());
            }
        }

        static void AddAttributes(COSE.Attributes msg, JSON items, bool fProtected)
        {
            foreach (KeyValuePair<string, JSON> attr in items.map) {
                CBORObject cborKey;
                CBORObject cborValue;

                if ((attr.Key.Length > 4) && (attr.Key.Substring(attr.Key.Length - 4, 4) == "_hex")) {
                    cborKey = CBORObject.FromObject(attr.Key.Substring(0, attr.Key.Length - 4));
                    cborValue = CBORObject.FromObject( FromHex(attr.Value.AsString()));
                }
                else cborValue = AsCbor(attr.Value);

                switch (attr.Key) {
                case "alg":
                    cborKey = COSE.HeaderKeys.Algorithm;
                    cborValue = AlgorithmMap(cborValue);
                    break;

                case "kid":
                    cborKey = COSE.HeaderKeys.KeyId;
                    break;

                default:
                    cborKey = CBORObject.FromObject(attr.Key);
                    break;
                }
                msg.AddAttribute(cborKey, cborValue, fProtected);
            }
        }

        static void AddAttributes(JOSE.Attributes msg, JSON items, bool fProtected)
        {
            foreach (KeyValuePair<string, JSON> key in items.map) {
                if ((key.Key.Length > 4) && (key.Key.Substring(key.Key.Length - 4, 4) == "_hex")) {
                    msg.AddAttribute(key.Key.Substring(0, key.Key.Length - 4), JOSE.Message.base64urlencode(FromHex(key.Value.AsString())), fProtected);
                }
                else msg.AddAttribute(key.Key, key.Value, fProtected);
            }
        }

        static COSE.Recipient GetRecipient(JSON control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Recipient missing alg field");

            COSE.Key key = GetKey(control["key"]);

            CBORObject alg = AlgorithmMap(CBORObject.FromObject(control["alg"].AsString()));
            COSE.Recipient recipient = new COSE.Recipient(key, alg);

            //  Double check that alg is the same as in the attributes

            if (control.ContainsKey("protected")) AddAttributes(recipient, control["protected"], true);
            if (control.ContainsKey("unprotected")) AddAttributes(recipient, control["unprotected"], false);

            if (control.ContainsKey("sender_key")) {
                COSE.Key myKey = GetKey(control["sender_key"]);
                recipient.SetSenderKey(myKey);
            }
            return recipient;
        }

        static JOSE.Recipient GetRecipientJOSE(JSON control)
        {
            JOSE.Key key;

            if (!control.ContainsKey("alg")) throw new Exception("Recipient missing alg field");

            if (control.ContainsKey("key")) {
                key = new JOSE.Key(control["key"]);
            }
            else if (control.ContainsKey("pwd")) {
                key = new JOSE.Key();
                key.Add("kty", "oct");
                key.Add("k", JOSE.Message.base64urlencode(UTF8Encoding.UTF8.GetBytes(  control["pwd"].AsString())));
            }
            else throw new Exception("No key defined for a recipient");

            JOSE.Recipient recipient = new JOSE.Recipient(key, control["alg"].AsString());

            //  Double check that alg is the same as in the attributes

            recipient.ClearProtected();
            recipient.ClearUnprotected();

            if (control.ContainsKey("protected_jose")) AddAttributes(recipient, control["protected_jose"], true);
            if (control.ContainsKey("unprotected_jose")) AddAttributes(recipient, control["unprotected_jose"], false);

            if (control.ContainsKey("sender_key")) {
                JOSE.Key myKey = new JOSE.Key(control["sender_key"]);
                recipient.SetSenderKey(myKey);
            }
            return recipient;
        }

        static COSE.Signer GetSigner(JSON control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Signer missing alg field");

            COSE.Key key = GetKey(control["key"]);

            COSE.Signer signer = new COSE.Signer(key, control["alg"].AsString());

            if (control.ContainsKey("protected")) AddAttributes(signer, control["protected"], true);
            if (control.ContainsKey("unprotected")) AddAttributes(signer, control["unprotected"], false);

            return signer;
        }

        static JOSE.Signer GetSignerJOSE(JSON control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Signer missing alg field");

            JOSE.Key key = new JOSE.Key(control["key"]);

            JOSE.Signer signer = new JOSE.Signer(key, control["alg"].AsString());

            if (control.ContainsKey("protected_jose")) AddAttributes(signer, control["protected_jose"], true);
            if (control.ContainsKey("unprotected_jose")) AddAttributes(signer, control["unprotected_jose"], false);

            return signer;
        }

        static COSE.Key GetKey(JSON control)
        {
            COSE.Key key = new COSE.Key();

            foreach (KeyValuePair<string, JSON> pair in control.map) {
                switch (pair.Key) {
                case "kty":
                case "kid":
                case "use":
                case "enc":
                case "crv":
                case "alg":
                    key.Add(pair.Key, pair.Value.AsString());
                    break;

                case "x":
                case "y":
                case "d":
                case "k":
                case "e":
                case "n":
                case "p":
                case "q":
                case "dp":
                case "dq":
                case "qi":
                    key.Add(pair.Key, base64urldecode(pair.Value.AsString()));
                    break;

                default:
                    throw new Exception("Unrecognized field name " + pair.Key + " in key object");
                }
            }
            return key;
        }

        static COSE.Key GetKey(JSON control)
        {
            COSE.Key key = new COSE.Key();

            foreach (KeyValuePair<string, JSON> pair in control.map) {
                switch (pair.Key) {
                case "kty":
                case "kid":
                case "use":
                case "enc":
                case "crv":
                case "alg":
                    key.Add(pair.Key, pair.Value.AsString());
                    break;

                case "x":
                case "y":
                case "d":
                case "k":
                case "e":
                case "n":
                case "p":
                case "q":
                case "dp":
                case "dq":
                case "qi":
                    key.Add(pair.Key, base64urldecode(pair.Value.AsString()));
                    break;

                default:
                    throw new Exception("Unrecognized field name " + pair.Key + " in key object");
                }
            }
            return key;
        }

        static byte[] base64urldecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
            case 0: break; // No pad chars in this case
            case 2: s += "=="; break; // Two pad chars
            case 3: s += "="; break; // One pad char
            default: throw new System.Exception(
              "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        static string ToHex(byte[] rgb)
        {
            string hex = BitConverter.ToString(rgb);
            return hex.Replace("-", "");
        }

        public static byte[] FromHex(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static CBORObject AsCbor(JSON json)
        {
            CBORObject obj;

            switch (json.nodeType) {
            case JsonType.array:
                obj = CBORObject.NewArray();
                foreach (JSON pair in json.array) {
                    obj.Add(AsCbor(pair));
                }
                return obj;

            case JsonType.map:
                obj = CBORObject.NewMap();
                foreach (KeyValuePair<string, JSON> pair in json.map) {
                    obj.Add(pair.Key, AsCbor(pair.Value));
                }
                return obj;

            case JsonType.number:
                return CBORObject.FromObject(json.number);

            case JsonType.text:
                return CBORObject.FromObject(json.text);

            case JsonType.unknown:
            default:
                throw new Exception("Can deal with unknown JSON node type");
            }


        }

        static CBORObject AlgorithmMap(CBORObject old)
        {
            switch (old.AsString()) {
            case "A128GCM": return COSE.AlgorithmValues.AES_GCM_128;
            case "A192GCM": return COSE.AlgorithmValues.AES_GCM_192;
            case "A256GCM": return COSE.AlgorithmValues.AES_GCM_256;
            case "A128KW": return COSE.AlgorithmValues.AES_KW_128;
            case "A192KW": return COSE.AlgorithmValues.AES_KW_192;
            case "A256KW": return COSE.AlgorithmValues.AES_KW_256;
            case "RSA-OAEP": return COSE.AlgorithmValues.RSA_OAEP;
            case "RSA-OAEP-256": return COSE.AlgorithmValues.RSA_OAEP_256;
            case "HS256": return COSE.AlgorithmValues.HMAC_SHA_256;
            case "HS512": return COSE.AlgorithmValues.HMAC_SHA_512;
            case "ES256": return COSE.AlgorithmValues.ECDSA_256;
            case "ES512": return COSE.AlgorithmValues.ECDSA_512;
                
            default: return old;
            }
        }
    }

    class BadOutputException : Exception 
    {
        public BadOutputException() : base("Output selection not supported for this input set") {}
    }
}
