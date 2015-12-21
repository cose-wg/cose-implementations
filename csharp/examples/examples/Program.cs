using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using PeterO.Cbor;
using JOSE;

namespace examples
{


    class Program
    {
        enum Outputs { cbor = 1, cborDiag = 2, jose = 3, jose_compact = 4, jose_flatten = 5 };

        static Outputs[] RgOutputs = new Outputs[] {Outputs.cborDiag, Outputs.cbor  /*, Outputs.cbor, Outputs.cborFlatten*/ };

        static COSE.KeySet allkeys = new COSE.KeySet();
        static COSE.KeySet allPubKeys = new COSE.KeySet();

        static void Main(string[] args)
        {
           //  COSE.Key.NewKey();

            RunTestsInDirectory("c:\\Projects\\COSE\\examples\\spec-examples");
            {
                byte[] result = allkeys.EncodeToBytes();

                FileStream bw = File.OpenWrite("c:\\Projects\\COSE\\examples\\spec-examples\\new\\private-keyset.bin");
                bw.SetLength(0);
                bw.Write(result, 0, result.Length);
                bw.Close();

                bw = File.OpenWrite("c:\\Projects\\COSE\\examples\\spec-examples\\new\\public-keyset.bin");
                bw.SetLength(0);
                result = allPubKeys.EncodeToBytes();
                bw.Write(result, 0, result.Length);
                bw.Close();

            }
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
            if (di.Name[0] == '.') return;
            StreamReader file = File.OpenText(di.FullName);
            string fileText = file.ReadToEnd();
            CBORObject control = CBORObject.FromJSONString(fileText);
            file.Close();

            if (!Directory.Exists(di.DirectoryName + "\\new")) Directory.CreateDirectory(di.DirectoryName + "\\new");

            try {
                if (ProcessJSON(control, di.DirectoryName + "\\new\\" + di.Name + ".bin")) {
                    fileText = control.ToJSONStringPretty(1);
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

        static bool ProcessJSON(CBORObject control, string fileName)
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
                if (control["input"]["rng_stream"].Type == CBORType.TextString) {
                    prng.AddSeedMaterial(FromHex(control["input"]["rng_stream"].AsString()));
                }
                else if (control["input"]["rng_stream"].Type == CBORType.Array) {
                    foreach (var x in control["input"]["rng_stream"].Values) {
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

                    if (control["input"].ContainsKey("mac")) result = ProcessMAC(output, control, ref modified);
                    else if (control["input"].ContainsKey("mac0")) result = ProcessMAC0(output, control, ref modified);
                    else if (control["input"].ContainsKey("enveloped")) result = ProcessEnveloped(output, control, ref modified);
                    else if (control["input"].ContainsKey("encrypted")) result = ProcessEncrypted(output, control, ref modified);
                    else if (control["input"].ContainsKey("sign")) result = ProcessSign(output, control);
                    else if (control["input"].ContainsKey("sign0")) result = ProcessSign0(output, control);
                    else throw new Exception("Unknown operation in control");

                    switch (output) {
                    case Outputs.cbor:
                        if (control["output"].ContainsKey(outputName)) {
                            byte[] rgbSource = FromHex(control["output"][outputName].AsString());
                            if (!rgbSource.SequenceEqual(result)) {
                                Console.WriteLine();
                                Console.WriteLine("******************* New and Old do not match!!!");
                                Console.WriteLine();


                                control["output"][outputName] = CBORObject.FromObject(ToHex(result));
                                modified = true;
                            }
                        }
                        else {
                            control["output"].Add(outputName, ToHex(result));
                            modified = true;
                        }
                        FileStream bw = File.OpenWrite(fileName);
                        bw.SetLength(0);
                        bw.Write(result, 0, result.Length);
                        bw.Close();
                        break;

                    case Outputs.cborDiag:
                        if (control["output"].ContainsKey(outputName)) {
                            string strSource = control["output"][outputName].ToString();
                            string strThis = UTF8Encoding.UTF8.GetString(result);

                            if (strSource != strThis) {
                                Console.WriteLine();
                                Console.WriteLine("******************* New and Old do not match!!!");
                                Console.WriteLine();

                                control["output"][outputName] = CBORObject.FromObject(strThis);
                                modified = true;
                            }
                        }
                        else {
                            control["output"].Add(outputName, UTF8Encoding.UTF8.GetString(result));
                            modified = true;
                        }
                        break;

                    default:
                        if (control["output"].ContainsKey(outputName)) {
                            string strSource = control["output"][outputName].ToString();
                            string strThis = UTF8Encoding.UTF8.GetString(result);

                            if (strSource != strThis) {
                                Console.WriteLine();
                                Console.WriteLine("******************* New and Old do not match!!!");
                                Console.WriteLine();


                                if (output == Outputs.jose_compact) control["output"][outputName] = CBORObject.FromObject(strThis);
                                else control["output"][outputName] = CBORObject.FromJSONString(strThis);
                                modified = true;
                            }
                        }
                        else {
                            if ((output == Outputs.jose) || (output == Outputs.jose_flatten)) {
                                control["output"].Add(outputName, JSON.Parse(UTF8Encoding.UTF8.GetString(result)));

                            }
                            else {
                                control["output"].Add(outputName, ToHex(result));
                            }
                        }
                        modified = true;
                        break;
                    }

                    if (prng.IsDirty) {
                        if (control["input"].ContainsKey("rng_stream")) control["input"]["rng_stream"] = CBORObject.FromObject(ToHex(prng.buffer));
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

        static byte[] ProcessSign(Outputs outputFormat, CBORObject control)
        {
            CBORObject input = control["input"];
            CBORObject sign = input["sign"];

            if (outputFormat < Outputs.jose) {
                COSE.SignMessage msg = new COSE.SignMessage();

                msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], 0);
                if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], 1);
                if (sign.ContainsKey("unsent")) AddAttributes(msg, sign["unsent"], 2);

                if ((!sign.ContainsKey("signers")) || (sign["signers"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                foreach (CBORObject recip in sign["signers"].Values) {
                    msg.AddSigner(GetSigner(recip));
                }

                if (outputFormat == Outputs.cborDiag) return UTF8Encoding.UTF8.GetBytes(msg.EncodeToCBORObject().ToString());
                return msg.EncodeToBytes();
            }
            else {
                JOSE.SignMessage msg = new JOSE.SignMessage();

                if (outputFormat != Outputs.jose_flatten) msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], true);
                if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], false);

                if ((!sign.ContainsKey("signers")) || (sign["signers"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                if ((sign["signers"].Count > 1) && (outputFormat == Outputs.jose_flatten)) throw new BadOutputException();
                foreach (CBORObject recip in sign["signers"].Values) {
                    msg.AddSigner(GetSignerJOSE(recip));
                }

                if (outputFormat == Outputs.jose_compact) return UTF8Encoding.UTF8.GetBytes(msg.EncodeCompact());
                return UTF8Encoding.UTF8.GetBytes(msg.Encode());
            }
        }

        static byte[] ProcessSign0(Outputs outputFormat, CBORObject control)
        {
            CBORObject input = control["input"];
            CBORObject sign = input["sign0"];

            COSE.Sign0Message msg = new COSE.Sign0Message();

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (!sign.ContainsKey("alg")) throw new Exception("Signer missing alg field");

            COSE.Key key = GetKey(sign["key"]);

            msg.AddSigner(key, AlgorithmMap(sign["alg"]));

            if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], 0);
            if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], 1);
            if (sign.ContainsKey("unsent")) AddAttributes(msg, sign["unsent"], 2);

            if (outputFormat == Outputs.cborDiag) return UTF8Encoding.UTF8.GetBytes(msg.EncodeToCBORObject().ToString());
            return msg.EncodeToBytes();
        }

        static byte[] ProcessEncrypted(Outputs outputFormat, CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject encrypt = input["encrypted"];

            if (outputFormat < Outputs.jose) {
                COSE.EnvelopeMessage msg = new COSE.EncryptMessage();

                msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (encrypt.ContainsKey("protected")) AddAttributes(msg, encrypt["protected"], 0);
                if (encrypt.ContainsKey("unprotected")) AddAttributes(msg, encrypt["unprotected"], 1);
                if (encrypt.ContainsKey("unsent")) AddAttributes(msg, encrypt["unsent"], 2);
                if (encrypt.ContainsKey("countersign")) AddCounterSignature(msg, encrypt["countersign"]);

                if (!encrypt.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                foreach (CBORObject recip in encrypt["recipients"].Values) {
                    msg.AddRecipient(GetRecipient(recip));
                }

                {
                    string aad = Convert.ToBase64String(msg.getAADBytes());
                    CBORObject intermediates;
                    if (!control.ContainsKey("intermediates")) {
                        intermediates = CBORObject.NewMap();
                        control.Add("intermediates", intermediates);
                        fDirty = true;
                    }
                    else {
                        intermediates = control["intermediates"];
                    }

                    string aad_old;
                    if (intermediates.ContainsKey("AAD")) {
                        aad_old = intermediates["AAD"].AsString();
                        if (aad_old != aad) {
                            intermediates["AAD"] = CBORObject.FromObject( aad);
                            fDirty = true;
                        }
                    }
                    else {
                        intermediates.Add("AAD", aad);
                        fDirty = true;
                    }
                }

                if (outputFormat == Outputs.cborDiag) return UTF8Encoding.UTF8.GetBytes(msg.EncodeToCBORObject().ToString());
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

                if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                if ((encrypt["recipients"].Count > 1) && (outputFormat != Outputs.jose)) throw new BadOutputException();

                foreach (CBORObject recip in encrypt["recipients"].Values) {
                    msg.AddRecipient(GetRecipientJOSE(recip));
                }

                if (outputFormat == Outputs.jose_compact) return UTF8Encoding.UTF8.GetBytes(msg.EncodeCompact());
                return UTF8Encoding.UTF8.GetBytes(msg.Encode());

            }
        }

        static byte[] ProcessEnveloped(Outputs outputFormat, CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject encrypt = input["enveloped"];

            if (outputFormat < Outputs.jose) {
                COSE.EnvelopeMessage msg = new COSE.EnvelopeMessage();

                msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (encrypt.ContainsKey("protected")) AddAttributes(msg, encrypt["protected"], 0);
                if (encrypt.ContainsKey("unprotected")) AddAttributes(msg, encrypt["unprotected"], 1);
                if (encrypt.ContainsKey("unsent")) AddAttributes(msg, encrypt["unsent"], 2);
                if (encrypt.ContainsKey("countersign")) AddCounterSignature(msg, encrypt["countersign"]);

                if (!encrypt.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                foreach (CBORObject recip in encrypt["recipients"].Values) {
                    msg.AddRecipient(GetRecipient(recip));
                }

                if (outputFormat == Outputs.cborDiag) {
                    msg.Encrypt();

                    string aad = Convert.ToBase64String(msg.getAADBytes());
                    CBORObject intermediates;
                    if (!control.ContainsKey("intermediates")) {
                        intermediates = CBORObject.NewMap();
                        control.Add("intermediates", intermediates);
                        fDirty = true;
                    }
                    else {
                        intermediates = control["intermediates"];
                    }

                    string aad_old;
                    if (intermediates.ContainsKey("AAD")) {
                        aad_old = intermediates["AAD"].AsString();
                        if (aad_old != aad) {
                            intermediates["AAD"] = CBORObject.FromObject(aad);
                            fDirty = true;
                        }
                    }
                    else {
                        intermediates.Add("AAD", aad);
                        fDirty = true;
                    }

                    CBORObject rList;
                    if (intermediates.ContainsKey("recipients")) rList = intermediates["recipients"];
                    else {
                        rList = CBORObject.NewArray();
                        intermediates.Add("recipients", rList);
                        fDirty = true;
                    }

                    for (int iRecipient = 0; iRecipient < msg.RecipientList.Count; iRecipient++) {
                        string foo = Convert.ToBase64String(msg.RecipientList[iRecipient].GetKDFInput(255, msg.FindAttribute(COSE.HeaderKeys.Algorithm)));
                        CBORObject r;
                        if (rList.Count <= iRecipient) {
                            r = CBORObject.NewMap();
                            rList.Add(r);
                            fDirty = true;
                        }
                        else r = rList[iRecipient];
            
                        if (r.ContainsKey("KDF")) {
                            if (foo != r["KDF"].AsString()) {
                                r["KDF"] = CBORObject.FromObject(foo);
                                fDirty = true;
                            }
                        }
                        else {
                            r.Add("KDF", foo);
                            fDirty = true;
                        }
                    }
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

                if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                if ((encrypt["recipients"].Count > 1) && (outputFormat != Outputs.jose)) throw new BadOutputException();

                foreach (CBORObject recip in encrypt["recipients"].Values) {
                    msg.AddRecipient(GetRecipientJOSE(recip));
                }

                if (outputFormat == Outputs.jose_compact) return UTF8Encoding.UTF8.GetBytes(msg.EncodeCompact());
                return UTF8Encoding.UTF8.GetBytes( msg.Encode());

            }
        }

        static byte[] ProcessMAC(Outputs outputFormat, CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject mac = input["mac"];

            if (outputFormat < Outputs.jose) {
                COSE.MACMessage msg = new COSE.MACMessage();

                msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (mac.ContainsKey("protected")) AddAttributes(msg, mac["protected"], 0);
                if (mac.ContainsKey("unprotected")) AddAttributes(msg, mac["unprotected"], 1);
                if (mac.ContainsKey("unsent")) AddAttributes(msg, mac["unsent"], 2);

                if (!mac.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!mac.ContainsKey("recipients")) || (mac["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                if ((mac["recipients"].Count > 1) && (outputFormat == Outputs.jose_flatten)) throw new BadOutputException();

                foreach (CBORObject recip in mac["recipients"].Values) {
                    msg.AddRecipient(GetRecipient(recip));
                }

                {
                    string aad = Convert.ToBase64String(msg.BuildContentBytes());
                    CBORObject intermediates;
                    if (!control.ContainsKey("intermediates")) {
                        intermediates = CBORObject.NewMap();
                        control.Add("intermediates", intermediates);
                        fDirty = true;
                    }
                    else {
                        intermediates = control["intermediates"];
                    }

                    string aad_old;
                    if (intermediates.ContainsKey("AAD")) {
                        aad_old = intermediates["AAD"].AsString();
                        if (aad_old != aad) {
                            intermediates["AAD"] = CBORObject.FromObject(aad);
                            fDirty = true;
                        }
                    }
                    else {
                        intermediates.Add("AAD", aad);
                        fDirty = true;
                    }
                }

                if (outputFormat == Outputs.cborDiag) return UTF8Encoding.UTF8.GetBytes(msg.EncodeToCBORObject().ToString());
                return msg.EncodeToBytes();
            }
            else {
                JOSE.SignMessage msg = new JOSE.SignMessage();

                if (outputFormat != Outputs.jose_flatten) msg.ForceArray(true);

                if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
                msg.SetContent(input["plaintext"].AsString());

                if (mac.ContainsKey("protected_jose")) AddAttributes(msg, mac["protected_jose"], true);
                if (mac.ContainsKey("unprotected_jose")) AddAttributes(msg, mac["unprotected_jose"], false);

                if (!mac.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
                //  Should check that this exists somewhere and has the correct value

                if ((!mac.ContainsKey("recipients")) || (mac["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                foreach (CBORObject recip in mac["recipients"].Values) {
                    msg.AddSigner(GetSignerJOSE(recip));
                }

                if (outputFormat == Outputs.jose_compact) return UTF8Encoding.UTF8.GetBytes(msg.EncodeCompact());
                return UTF8Encoding.UTF8.GetBytes(msg.Encode());
            }
        }

        static byte[] ProcessMAC0(Outputs outputFormat, CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject mac = input["mac0"];

            COSE.MAC0Message msg = new COSE.MAC0Message();

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (mac.ContainsKey("protected")) AddAttributes(msg, mac["protected"], 0);
            if (mac.ContainsKey("unprotected")) AddAttributes(msg, mac["unprotected"], 1);
            if (mac.ContainsKey("unsent")) AddAttributes(msg, mac["unsent"], 2);

            if (!mac.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
            //  Should check that this exists somewhere and has the correct value

            if ((!mac.ContainsKey("recipients")) || (mac["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
            if ((mac["recipients"].Count > 1) && (outputFormat == Outputs.jose_flatten)) throw new BadOutputException();

            foreach (CBORObject recip in mac["recipients"].Values) {
                msg.AddRecipient(GetRecipient(recip));
            }

            {
                string aad = Convert.ToBase64String(msg.BuildContentBytes());
                CBORObject intermediates;
                if (!control.ContainsKey("intermediates")) {
                    intermediates = CBORObject.NewMap();
                    control.Add("intermediates", intermediates);
                    fDirty = true;
                }
                else {
                    intermediates = control["intermediates"];
                }

                string aad_old;
                if (intermediates.ContainsKey("AAD")) {
                    aad_old = intermediates["AAD"].AsString();
                    if (aad_old != aad) {
                        intermediates["AAD"] = CBORObject.FromObject(aad);
                        fDirty = true;
                    }
                }
                else {
                    intermediates.Add("AAD", aad);
                    fDirty = true;
                }
            }

            if (outputFormat == Outputs.cborDiag) return UTF8Encoding.UTF8.GetBytes(msg.EncodeToCBORObject().ToString());
            return msg.EncodeToBytes();
        }

        static void AddAttributes(COSE.Attributes msg, CBORObject items, int destination)
        {
            foreach (CBORObject cborKey2 in items.Keys) {
                CBORObject cborValue = items[cborKey2];
                CBORObject cborKey = cborKey2;
                string strKey = cborKey.AsString();

                if ((strKey.Length > 4) && (strKey.Substring(strKey.Length - 4, 4) == "_hex")) {
                    cborKey = CBORObject.FromObject(strKey.Substring(0, strKey.Length - 4));
                    cborValue = CBORObject.FromObject( FromHex(cborValue.AsString()));
                }

                switch (cborKey.AsString()) {
                case "alg":
                    cborKey = COSE.HeaderKeys.Algorithm;
                    cborValue = AlgorithmMap(cborValue);
                    break;

                case "kid":
                    cborKey = COSE.HeaderKeys.KeyId;
                binFromText:
                    if (cborValue.Type == CBORType.TextString) cborValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cborValue.AsString()));
                    break;

                case"epk":
                    cborKey = COSE.HeaderKeys.EphemeralKey;
                    break;

                case "salt": cborKey = COSE.CoseKeyParameterKeys.HKDF_Salt; goto binFromText;
                case "apu_id": cborKey = COSE.CoseKeyParameterKeys.HKDF_Context_PartyU_ID; goto binFromText;
                case "apv_id": cborKey = COSE.CoseKeyParameterKeys.HKDF_Context_PartyV_ID; goto binFromText;
                case "supp_pub_other": cborKey = COSE.CoseKeyParameterKeys.HKDF_SuppPub_Other; goto binFromText;
                case "spk_kid": cborKey = COSE.CoseKeyParameterKeys.ECDH_StaticKey_kid; goto binFromText;

                case "IV": cborKey = COSE.HeaderKeys.IV; goto binFromText;
                case "partialIV": cborKey = COSE.HeaderKeys.PartialIV; goto binFromText;
#if false
                    if (cborValue.Type == CBORType.TextString) {
                        cborValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cborValue.AsString()));
                    }
                    if (cborValue.Type == CBORType.ByteString) {
                        byte[] bytes = cborValue.GetByteString();
                        if (bytes.Length != 2) throw new Exception("Incorrect size for bytes->int");
                        cborValue = CBORObject.FromObject(bytes[0] * 256 + bytes[1]);
                    }
                    break;
#endif

                default:
                    break;
                }

                switch (destination) {
                case 0: msg.AddAttribute(cborKey, cborValue, true); break;
                case 1: msg.AddAttribute(cborKey, cborValue, false); break;
                case 2: msg.AddDontSend(cborKey, cborValue); break;
                }
            }
        }

        static void AddAttributes(JOSE.Attributes msg, CBORObject items, bool fProtected)
        {
            foreach (CBORObject key in items.Keys) {
                if ((key.AsString().Length > 4) && (key.AsString().Substring(key.AsString().Length - 4, 4) == "_hex")) {
                    msg.AddAttribute(key.AsString().Substring(0, key.AsString().Length - 4), JOSE.Message.base64urlencode(FromHex(items[key].AsString())), fProtected);
                }
                else msg.AddAttribute(key.AsString(), items[key].AsString(), fProtected);
            }
        }

        static void AddCounterSignature(COSE.Message msg, CBORObject items)
        {
            if (items.Type == CBORType.Map) {
                if ((!items.ContainsKey("signers")) || (items["signers"].Type != CBORType.Array)) throw new Exception("Missing or malformed counter signatures");
                foreach (CBORObject recip in items["signers"].Values) {
                    msg.AddCounterSignature(GetSigner(recip));
                }
            }
        }

        static COSE.Recipient GetRecipient(CBORObject control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Recipient missing alg field");

            COSE.Key key = null;
            
            if (control["key"] != null) key = GetKey(control["key"]);

            CBORObject alg = AlgorithmMap(CBORObject.FromObject(control["alg"].AsString()));
            COSE.Recipient recipient = new COSE.Recipient(key, alg);

            //  Double check that alg is the same as in the attributes

            if (control.ContainsKey("protected")) AddAttributes(recipient, control["protected"], 0);
            if (control.ContainsKey("unprotected")) AddAttributes(recipient, control["unprotected"], 1);
            if (control.ContainsKey("unsent")) AddAttributes(recipient, control["unsent"], 2);

            if (control.ContainsKey("recipients")) {
                if ((!control.ContainsKey("recipients")) || (control["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                foreach (CBORObject recip in control["recipients"].Values) {
                    recipient.AddRecipient(GetRecipient(recip));
                }
            }

            if (control.ContainsKey("sender_key")) {
                COSE.Key myKey = GetKey(control["sender_key"]);
                recipient.SetSenderKey(myKey);
            }
            return recipient;
        }

        static JOSE.Recipient GetRecipientJOSE(CBORObject control)
        {
            JOSE.Key key;

            if (!control.ContainsKey("alg")) throw new Exception("Recipient missing alg field");

            if (control.ContainsKey("key")) {
                key = new JOSE.Key(JSON.Parse(control["key"].ToJSONString()));
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
                JOSE.Key myKey = new JOSE.Key(JSON.Parse(control["sender_key"].ToJSONString()));
                recipient.SetSenderKey(myKey);
            }
            return recipient;
        }

        static COSE.Signer GetSigner(CBORObject control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Signer missing alg field");

            COSE.Key key = GetKey(control["key"]);

            COSE.Signer signer = new COSE.Signer(key, control["alg"]);

            if (control.ContainsKey("protected")) AddAttributes(signer, control["protected"], 0);
            if (control.ContainsKey("unprotected")) AddAttributes(signer, control["unprotected"], 1);
            if (control.ContainsKey("unsent")) AddAttributes(signer, control["unsent"], 2);

            return signer;
        }

        static JOSE.Signer GetSignerJOSE(CBORObject control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Signer missing alg field");

            JOSE.Key key = new JOSE.Key(JSON.Parse(control["key"].ToJSONString()));

            JOSE.Signer signer = new JOSE.Signer(key, control["alg"].AsString());

            if (control.ContainsKey("protected_jose")) AddAttributes(signer, control["protected_jose"], true);
            if (control.ContainsKey("unprotected_jose")) AddAttributes(signer, control["unprotected_jose"], false);

            return signer;
        }

        static COSE.Key GetKey(CBORObject control)
        {
            COSE.Key key = new COSE.Key();
            CBORObject newKey;
            CBORObject newValue;
            string type = control["kty"].AsString();

            foreach (CBORObject item in control.Keys) { 
                switch (item.AsString()) {
                case "kty":
                    newKey = COSE.CoseKeyKeys.KeyType;
                    switch (control[item].AsString()) {
                    case "EC": newValue = COSE.GeneralValues.KeyType_EC; goto NewValue;
                    case "RSA": newValue = COSE.GeneralValues.KeyType_RSA; goto NewValue;
                    case "oct": newValue = COSE.GeneralValues.KeyType_Octet; goto NewValue;
                    default:
                        break;
                    }
                TextValue:
                    key.Add(newKey, control[item]);
                    break;

                case "kid":
                    newKey = COSE.CoseKeyKeys.KeyIdentifier;
                    newValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(control[item].AsString()));
                    goto NewValue;

                case "kid_hex":
                    newKey = COSE.CoseKeyKeys.KeyIdentifier;
                BinaryValue:
                    key.Add(newKey, CBORObject.FromObject(base64urldecode(control[item].AsString())));
                    break;

                case "alg":
                    newKey = COSE.CoseKeyKeys.Algorithm;
                    goto TextValue;

                    // ECDSA parameters
                case "crv":
                    newKey = COSE.CoseKeyParameterKeys.EC_Curve;
                    switch (control[item].AsString()) {
                    case "P-256":
                        newValue = COSE.GeneralValues.P256;
                        break;

                    case "P-521":
                        newValue = COSE.GeneralValues.P521;
                        break;

                    default:
                        newValue = control[item];
                        break;
                    }
                NewValue:
                    key.Add(newKey, newValue);
                    break;

                case "use":
                    break;

                case "enc":
                    key.Add(item, control[item]);
                    break;

                case "x": newKey = COSE.CoseKeyParameterKeys.EC_X; goto BinaryValue;
                case "y": newKey = COSE.CoseKeyParameterKeys.EC_Y; goto BinaryValue;

                case "e": newKey = COSE.CoseKeyParameterKeys.RSA_e; goto BinaryValue;
                case "n": newKey = COSE.CoseKeyParameterKeys.RSA_n; goto BinaryValue;

                case "d":
                    if (type == "RSA") newKey = COSE.CoseKeyParameterKeys.RSA_d;
                    else newKey = COSE.CoseKeyParameterKeys.EC_D;
                    goto BinaryValue;
                case "k": newKey = COSE.CoseKeyParameterKeys.Octet_k; goto BinaryValue;
                case "p": newKey = COSE.CoseKeyParameterKeys.RSA_p; goto BinaryValue;
                case "q": newKey = COSE.CoseKeyParameterKeys.RSA_q; goto BinaryValue;
                case "dp": newKey = COSE.CoseKeyParameterKeys.RSA_dP; goto BinaryValue;
                case "dq": newKey = COSE.CoseKeyParameterKeys.RSA_dQ; goto BinaryValue;
                case "qi": newKey = COSE.CoseKeyParameterKeys.RSA_qInv; goto BinaryValue;

                default:
                    throw new Exception("Unrecognized field name " + item.AsString() + " in key object");
                }
            }

            allkeys.AddKey(key);

            COSE.Key pubKey = key.PublicKey();
            if (pubKey != null) {
                allPubKeys.AddKey(key.PublicKey());
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
            case "PS256": return COSE.AlgorithmValues.RSA_PSS_256;
            case "PS512": return COSE.AlgorithmValues.RSA_PSS_512;
            case "direct": return COSE.AlgorithmValues.Direct;
            case "AES-CMAC-128/64": return COSE.AlgorithmValues.AES_CMAC_128_64;
            case "AES-CMAC-256/64": return COSE.AlgorithmValues.AES_CMAC_256_64;
            case "AES-CCM-16-128/64": return COSE.AlgorithmValues.AES_CCM_16_64_128;
            case "dir+kdf": return COSE.AlgorithmValues.dir_kdf;
            case "ECDH-ES": return COSE.AlgorithmValues.ECDH_ES_HKDF_256;
            case "ECDH-SS": return COSE.AlgorithmValues.ECDH_SS_HKDF_256;
            case "ECDH-ES+A128KW": return COSE.AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_128;
            case "ECDH-SS+A128KW": return COSE.AlgorithmValues.ECDH_SS_HKDF_256_AES_KW_128;

            default: return old;
            }
        }

    }

    class BadOutputException : Exception 
    {
        public BadOutputException() : base("Output selection not supported for this input set") {}
    }
}
