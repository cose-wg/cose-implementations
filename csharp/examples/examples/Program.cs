using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

using PeterO.Cbor;

namespace examples
{


    class Program
    {
        enum Outputs { cbor=1, cborFlatten=2 };

        static Outputs[] RgOutputs = new Outputs[] { Outputs.cbor, Outputs.cborFlatten };

        static void Main(string[] args)
        {
            RunTestsInDirectory("d:\\Projects\\COSE\\examples-contrib");
#if false
            SignExamples();
            EncryptionExamples();
            MacExamples();
#endif // false
        }

        static void RunTestsInDirectory(string strDirectory)
        {
            DirectoryInfo diTop;

            diTop = new DirectoryInfo(strDirectory);
            foreach (var di in diTop.EnumerateDirectories()) {
                RunTestsInDirectory(di.FullName);
            }

            foreach (var di in diTop.EnumerateFiles()) {
                if (di.Extension == ".json") {
                    ProcessFile(di.FullName);
                }
            }
        }

        static void ProcessFile(string strFileName)
        {
            StreamReader file = File.OpenText(strFileName);
            string fileText = file.ReadToEnd();
            JSON control = new JSON(fileText);
            file.Close();

            try {
                if (ProcessJSON(control)) {
                    fileText = control.Serialize();
                    StreamWriter file2 = File.CreateText(strFileName + ".new");
                    file2.Write(fileText);
                    file2.Write("\n");
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
                prng.AddSeedMaterial(FromHex(control["input"]["rng_stream"].AsString()));
            }
            COSE.Message.SetPRNG(prng);

            foreach (Outputs output in RgOutputs) {
                string outputName;
                switch (output) {
                case Outputs.cbor: outputName = "cbor"; break;
                case Outputs.cborFlatten: outputName = "cbor_flat"; break;
                default: outputName = ""; break;
                }

                prng.Reset();

                try {
                    byte[] result;

                    if (control["input"].ContainsKey("mac")) result = ProcessMAC(output, control);
                    else throw new Exception("Unknown operation in control");

                    if (control["output"].ContainsKey(outputName)) {
                        byte[] rgbSource = FromHex(control["output"][outputName].AsString());
                        if (rgbSource != result) {
                            Console.WriteLine();
                            Console.WriteLine("******************* New and Old do not match!!!");
                            Console.WriteLine();

                            control["output"][outputName].Set(ToHex(result));
                            modified = true;
                        }
                    }
                    else {
                        control["output"].Add(outputName, ToHex(result));
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
            }

            return modified;
        }



        static void SignExamples()
        {
            //  Signing Example #1 - ECDSA-256 - flattened

            {
                COSE.Key key = new COSE.Key();

                key.Add("kty", "RSA");
                key.Add("kid", "bilbo.baggins@hobbiton.example");
                key.Add("use", "sig");
                key.Add("n", base64urldecode("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw"));
                key.Add("e", base64urldecode("AQAB"));
                key.Add("d", base64urldecode("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ"));
                key.Add("p", base64urldecode("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k"));
                key.Add("q", base64urldecode("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc"));
                key.Add("dp", base64urldecode("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik"));
                key.Add("dq", base64urldecode("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8"));
                key.Add("qi", base64urldecode("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"));

                COSE.Key key2 = new COSE.Key();

                key2.Add("kty", "EC");
                key2.Add("kid", "bilbo.baggins@hobbiton.example");
                key2.Add("use", "sig");
                key2.Add("crv", "P-521");
                key2.Add("x", base64urldecode("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"));
                key2.Add("y", base64urldecode("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"));
                key2.Add("d", base64urldecode("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"));


                COSE.SignMessage msg = new COSE.SignMessage();
                msg.SetContent("Content String");

                COSE.Signer signer = new COSE.Signer(key);
                msg.AddSigner(signer);

                signer = new COSE.Signer(key2);
                msg.AddSigner(signer);

                byte[] rgb = msg.EncodeToBytes();

                Console.WriteLine("Direct Encoding Example:");
                Console.WriteLine("Line Length is " + rgb.Length);
                Console.WriteLine(BitConverter.ToString(rgb).Replace('-', ' '));
                string strT = BitConverter.ToString(rgb).Replace('-', ' ');
                Console.WriteLine();

                byte[] rgb2 = msg.BEncodeToBytes();
                Console.WriteLine("Borman Encodeing:");
                Console.WriteLine("Line Length is " + rgb2.Length);
                Console.WriteLine(BitConverter.ToString(rgb2).Replace('-', ' '));
                string strT2 = BitConverter.ToString(rgb2).Replace('-', ' ');
                Console.WriteLine();

#if false
            COSE.PrettyPrint pp = new COSE.PrettyPrint();
            String str = pp.PrintCBOR(rgb);
            Console.WriteLine(str);
#endif
            }

            //  Signing Example #2 - PS512 - array

            {
                COSE.Key key = new COSE.Key();

                key.Add("kty", "RSA");
                key.Add("kid", "bilbo.baggins@hobbiton.example");
                key.Add("use", "sig");
                key.Add("n", base64urldecode("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw"));
                key.Add("e", base64urldecode("AQAB"));
                key.Add("d", base64urldecode("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ"));
                key.Add("p", base64urldecode("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k"));
                key.Add("q", base64urldecode("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc"));
                key.Add("dp", base64urldecode("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik"));
                key.Add("dq", base64urldecode("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8"));
                key.Add("qi", base64urldecode("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"));

                COSE.Key key2 = new COSE.Key();

                key2.Add("kty", "EC");
                key2.Add("kid", "bilbo.baggins@hobbiton.example");
                key2.Add("use", "sig");
                key2.Add("crv", "P-521");
                key2.Add("x", base64urldecode("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"));
                key2.Add("y", base64urldecode("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"));
                key2.Add("d", base64urldecode("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"));


                COSE.SignMessage msg = new COSE.SignMessage();
                msg.SetContent("Content String");

                COSE.Signer signer = new COSE.Signer(key);
                msg.AddSigner(signer);

                signer = new COSE.Signer(key2);
                msg.AddSigner(signer);

                byte[] rgb = msg.EncodeToBytes();

                Console.WriteLine("Direct Encoding Example:");
                Console.WriteLine("Line Length is " + rgb.Length);
                Console.WriteLine(BitConverter.ToString(rgb).Replace('-', ' '));
                string strT = BitConverter.ToString(rgb).Replace('-', ' ');
                Console.WriteLine();

                byte[] rgb2 = msg.BEncodeToBytes();
                Console.WriteLine("Borman Encodeing:");
                Console.WriteLine("Line Length is " + rgb2.Length);
                Console.WriteLine(BitConverter.ToString(rgb2).Replace('-', ' '));
                string strT2 = BitConverter.ToString(rgb2).Replace('-', ' ');
                Console.WriteLine();

#if false
            COSE.PrettyPrint pp = new COSE.PrettyPrint();
            String str = pp.PrintCBOR(rgb);
            Console.WriteLine(str);
#endif
            }

            //  Signing Example #3 - Multiple Signers
            //      #1 - ES256
            //      #2 - ES512
            //      #3 - PS256

            {
                COSE.Key key = new COSE.Key();

                key.Add("kty", "RSA");
                key.Add("kid", "bilbo.baggins@hobbiton.example");
                key.Add("use", "sig");
                key.Add("n", base64urldecode("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw"));
                key.Add("e", base64urldecode("AQAB"));
                key.Add("d", base64urldecode("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ"));
                key.Add("p", base64urldecode("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k"));
                key.Add("q", base64urldecode("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc"));
                key.Add("dp", base64urldecode("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik"));
                key.Add("dq", base64urldecode("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8"));
                key.Add("qi", base64urldecode("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"));

                COSE.Key key2 = new COSE.Key();

                key2.Add("kty", "EC");
                key2.Add("kid", "bilbo.baggins@hobbiton.example");
                key2.Add("use", "sig");
                key2.Add("crv", "P-521");
                key2.Add("x", base64urldecode("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"));
                key2.Add("y", base64urldecode("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"));
                key2.Add("d", base64urldecode("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"));


                COSE.SignMessage msg = new COSE.SignMessage();
                msg.SetContent("Content String");

                COSE.Signer signer = new COSE.Signer(key);
                msg.AddSigner(signer);

                signer = new COSE.Signer(key2);
                msg.AddSigner(signer);

                byte[] rgb = msg.EncodeToBytes();

                Console.WriteLine("Direct Encoding Example:");
                Console.WriteLine("Line Length is " + rgb.Length);
                Console.WriteLine(BitConverter.ToString(rgb).Replace('-', ' '));
                string strT = BitConverter.ToString(rgb).Replace('-', ' ');
                Console.WriteLine();

                byte[] rgb2 = msg.BEncodeToBytes();
                Console.WriteLine("Borman Encodeing:");
                Console.WriteLine("Line Length is " + rgb2.Length);
                Console.WriteLine(BitConverter.ToString(rgb2).Replace('-', ' '));
                string strT2 = BitConverter.ToString(rgb2).Replace('-', ' ');
                Console.WriteLine();

#if false
            COSE.PrettyPrint pp = new COSE.PrettyPrint();
            String str = pp.PrintCBOR(rgb);
            Console.WriteLine(str);
#endif
            }

        }

        static void EncryptionExamples()
        {
#if false
            Encrypt - no array
     CE: AES-CCM-64
     KM: AES-KW
Encrypt - one element array
     CE: AES-GCM
     KM: RSA-OAEP
Encrypt - multiple recipient
     CE: AES-GCM
     KM: RSA-OAEP
     KM: ECDH + AES KW
     KM: AES-GCM-KW
Encrypt - three layer - flat
     CE: AES-GCM
     KM: AES-KW
     KM(layer 2): ECHD - SS - Direct
#endif

            //  Direct encryption example
            if (true) {
                COSE.EncryptMessage msg = new COSE.EncryptMessage();

                msg.SetContent("Content String");

                COSE.Key key = new COSE.Key();
                key.Add("kty", "oct");
                key.Add("kid", "77c7e2b8-6e13-45cf-8672-617b5b45243a");
                key.Add("use", "enc");
                key.Add("alg", "A128GCM");
                key.Add("k", base64urldecode("XctOhJAkA-pD9Lh7ZgW_2A"));


                COSE.Recipient recipient = new COSE.Recipient(key, "dir");
                msg.AddRecipient(recipient);

                byte[] rgb = msg.EncodeToBytes();

                Console.WriteLine("Direct Encoding Example:");
                Console.WriteLine("Line Length is " + rgb.Length);
                Console.WriteLine(BitConverter.ToString(rgb).Replace('-', ' '));
                string strT = BitConverter.ToString(rgb).Replace('-', ' ');
                Console.WriteLine();

                COSE.EncryptMessage msg2 = (COSE.EncryptMessage) COSE.Message.DecodeFromBytes(rgb);

                msg2.Decrypt(key);
            }

            //  Key wrap example
            if (true) {
                COSE.EncryptMessage msg = new COSE.EncryptMessage();

                msg.SetContent("Content String");

                COSE.Key key = new COSE.Key();
                key.Add("kty", "oct");
                key.Add("kid", "77c7e2b8-6e13-45cf-8672-617b5b45243a");
                key.Add("use", "enc");
                key.Add("alg", "A128GCM");
                key.Add("k", base64urldecode("XctOhJAkA-pD9Lh7ZgW_2A"));


                COSE.Recipient recipient = new COSE.Recipient(key);
                msg.AddRecipient(recipient);

                byte[] rgb = msg.EncodeToBytes();

                Console.WriteLine("Key Wrap Encoding Example:");
                Console.WriteLine("Line Length is " + rgb.Length);
                Console.WriteLine(BitConverter.ToString(rgb).Replace('-', ' '));
                string strT = BitConverter.ToString(rgb).Replace('-', ' ');
                Console.WriteLine();

                COSE.EncryptMessage msg2 = (COSE.EncryptMessage) COSE.Message.DecodeFromBytes(rgb);

                msg2.Decrypt(key);
            }

            // ECDH Example - Direct
            if (true) {
                COSE.Key key = new COSE.Key();

                key.Add("kty", "EC");
                key.Add("kid", "meriadoc.brandybuck@buckland.example");
                key.Add("use", "enc");
                key.Add("crv", "P-256");
                key.Add("x", base64urldecode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"));
                key.Add("y", base64urldecode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"));
                key.Add("d", base64urldecode("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"));

                COSE.EncryptMessage msg = new COSE.EncryptMessage();

                msg.SetContent("Content String");

                COSE.Recipient recipient = new COSE.Recipient(key, "ECDH-ES");
                msg.AddRecipient(recipient);

                byte[] rgb = msg.EncodeToBytes();

                Console.WriteLine("ECDH direct Encoding Example:");
                Console.WriteLine("Line Length is " + rgb.Length);
                Console.WriteLine(BitConverter.ToString(rgb).Replace('-', ' '));
                string strT = BitConverter.ToString(rgb).Replace('-', ' ');
                Console.WriteLine();

                COSE.EncryptMessage msg2 = (COSE.EncryptMessage) COSE.Message.DecodeFromBytes(rgb);

                msg2.Decrypt(key);
            }

            // ECDH + keywrap example
            if (true) {
                COSE.Key key = new COSE.Key();

                key.Add("kty", "EC");
                key.Add("kid", "meriadoc.brandybuck@buckland.example");
                key.Add("use", "enc");
                key.Add("crv", "P-256");
                key.Add("x", base64urldecode("Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0"));
                key.Add("y", base64urldecode("HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"));
                key.Add("d", base64urldecode("r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"));

                COSE.EncryptMessage msg = new COSE.EncryptMessage();

                msg.SetContent("Content String");

                COSE.Recipient recipient = new COSE.Recipient(key);
                msg.AddRecipient(recipient);

                byte[] rgb = msg.EncodeToBytes();

                Console.WriteLine("ECDH direct Encoding Example:");
                Console.WriteLine("Line Length is " + rgb.Length);
                Console.WriteLine(BitConverter.ToString(rgb).Replace('-', ' '));
                string strT = BitConverter.ToString(rgb).Replace('-', ' ');
                Console.WriteLine();

                COSE.EncryptMessage msg2 = (COSE.EncryptMessage) COSE.Message.DecodeFromBytes(rgb);

                msg2.Decrypt(key);

            }
        }

        static byte[] ProcessMAC(Outputs outputFormat, JSON control)
        {
            COSE.MACMessage msg = new COSE.MACMessage();

            if (outputFormat != Outputs.cborFlatten) msg.ForceArray(true);

            JSON input = control["input"];

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            JSON mac = input["mac"];

            if (mac.ContainsKey("protected")) AddAttributes(msg, mac["protected"], true);
            if (mac.ContainsKey("unprotected")) AddAttributes(msg, mac["unprotected"], false);

            if (!mac.ContainsKey("alg")) throw new Exception("missing algorithm identifier");
            //  Should check that this exists somewhere and has the correct value

            if ((!mac.ContainsKey("recipients")) || (mac["recipients"].nodeType != JsonType.array)) throw new Exception("Missing or malformed recipients");
            foreach (JSON recip in mac["recipients"].array) {
                msg.AddRecipient(GetRecipient(recip));
            }

            return msg.EncodeToBytes();
        }

        static void AddAttributes(COSE.Message msg, JSON items, bool fProtected)
        {
            foreach (KeyValuePair<string, JSON> key in items.map) {
                if ((key.Key.Length > 4) && (key.Key.Substring(key.Key.Length - 4, 4) == "_hex")) {
                    msg.AddAttribute(key.Key.Substring(0, key.Key.Length - 4), CBORObject.FromObject(FromHex(key.Value.AsString())), fProtected);
                }
                else msg.AddAttribute(key.Key, key.Value.AsCbor(), fProtected);
            }
        }

        static COSE.Recipient GetRecipient(JSON control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Recipient missing alg field");

            COSE.Key key = GetKey(control["key"]);

            COSE.Recipient recipient = new COSE.Recipient(key, control["alg"].AsString());

            //  Double check that alg is the same as in the attributes

            if (control.ContainsKey("protected")) AddAttributes(recipient, control["protected"], true);
            if (control.ContainsKey("unprotected")) AddAttributes(recipient, control["unprotected"], false);

            if (control.ContainsKey("sender_key")) {
                COSE.Key myKey = GetKey(control["sender_key"]);
                recipient.SetSenderKey(myKey);
            }
            return recipient;
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
    }

    class BadOutputException : Exception 
    {
        public BadOutputException() : base("Output selection not supported for this input set") {}
    }
}
