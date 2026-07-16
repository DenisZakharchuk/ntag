using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;

namespace MacCounter
{
    
    public static class MishaAlg
    {
        public static bool Verify(string url, byte[] sdmFileReadKey)
        {
            var uri = new Uri(url);
            var query = ParseQuery(uri.Query);

            var uidHex = query["uid"];
            var counterHex = query["ctr"];
            var macHex = query["mac"];

            var macInput = uri.Query.TrimStart('?');
            var index = macInput.IndexOf("mac=", StringComparison.Ordinal);
            macInput = macInput[..(index + 4)];
            byte[] uid = Convert.FromHexString(uidHex);
            uint ctr = Convert.ToUInt32(counterHex, 16);
            byte[] ctrLsb = new byte[]
            {
                (byte)(ctr & 0xFF),
                (byte)((ctr >> 8) & 0xFF),
                (byte)((ctr >> 16) & 0xFF)
            };

            return VerifyCore(uid, ctrLsb, macInput, sdmFileReadKey, macHex);
        }

        /// <summary>
        /// The actual CMAC verification steps, factored out of <see cref="Verify"/> so
        /// callers that have already parsed a UID/counter/MAC-input/expected-MAC (e.g. a
        /// benchmark comparing this against a Span-based implementation) can invoke it
        /// directly, without also paying for URL/query-string parsing.
        /// </summary>
        public static bool VerifyCore(byte[] uid, byte[] counterLsb, string macInputAscii, byte[] key, string expectedMacHex)
        {
            byte[] sv2 = BuildSv2(uid, counterLsb);
            byte[] kSecMac = ComputeCmac(key, sv2);
            byte[] cmac = ComputeCmac(kSecMac, Encoding.ASCII.GetBytes(macInputAscii));
            byte[] mac = TruncateCmac(cmac);

            return Convert.ToHexString(mac).Equals(expectedMacHex, StringComparison.OrdinalIgnoreCase);
        }

        private static Dictionary<string, string> ParseQuery(string query)
        {
            return query.TrimStart('?')
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => part.Split('=', 2))
                .ToDictionary(split => Uri.UnescapeDataString(split[0]), split => Uri.UnescapeDataString(split[1]));
        }

        private static byte[] BuildSv2(byte[] uid, byte[] counter)
        {
            if (uid.Length != 7) throw new ArgumentException("UID must be 7 bytes.", nameof(uid));
            if (counter.Length != 3) throw new ArgumentException("Counter must be 3 bytes.", nameof(counter));

            byte[] sv2 = new byte[16];
            sv2[0] = 0x3C;
            sv2[1] = 0xC3;
            sv2[2] = 0x00;
            sv2[3] = 0x01;
            sv2[4] = 0x00;
            sv2[5] = 0x80;
            uid.CopyTo(sv2, 6);
            counter.CopyTo(sv2, 13);
            return sv2;
        }

        private static byte[] ComputeCmac(byte[] key, byte[] message)
        {
            var cmac = new CMac(new AesEngine());
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(message, 0, message.Length);
            byte[] output = new byte[cmac.GetMacSize()];
            cmac.DoFinal(output, 0);
            return output;
        }
        private static byte[] TruncateCmac(byte[] fullCmac, int truncatedLength = 8)
        {
            if (truncatedLength <= 0 || truncatedLength > fullCmac.Length)
                throw new ArgumentOutOfRangeException(nameof(truncatedLength), "Truncated length must be positive and less than or equal to the full CMAC length.");

            byte[] truncated = new byte[truncatedLength];
            for (int i = 0; i < truncatedLength; i++)
            {
                truncated[i] = fullCmac[i * 2 + 1]; // Odd-byte truncation
            }
            return truncated;
        }
    }

    public static class Program
    {
        public static void Main(string[] args)
        {
            string url = args.Length > 0
                ? args[0]
                : "https://example.com/?serial=11111111&uid=04B43132502390&ctr=000001&mac=E7D76C550FF1755B";
            string keyBase64 = args.Length > 1
                ? args[1]
                : "c55sauQ+2NDG3ZX6P0Yz+Q==";

            byte[] key = Convert.FromBase64String(keyBase64);

            bool result = MishaAlg.Verify(url, key);

            Console.WriteLine($"URL: {url}");
            Console.WriteLine($"Key (b64): {keyBase64}");
            Console.WriteLine($"Verify result: {result}");
        }
    }
}
