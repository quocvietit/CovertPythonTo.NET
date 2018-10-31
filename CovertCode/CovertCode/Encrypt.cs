using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace CovertCode
{
    class Encrypt
    {
        string _key;
        string _kiloChallenge;
        byte[] _header;

        public Encrypt(string key, string kiloChallenge)
        {
            this._key = key;
            this._kiloChallenge = kiloChallenge;
            this._header = new byte[0x20]; //value: 32
        }

        public byte[] KeyTransform(string oldKey)
        {
            byte[] oldKeyByte = Encoding.ASCII.GetBytes(oldKey);
            byte[] newKey = new byte[oldKeyByte.Length];
            for (int x = 32; x > 0; x--)
            {
                byte b = oldKeyByte[x - 1];
                newKey[oldKeyByte.Length - x] = (byte)(b - (x % 12));
            }

            return newKey;
        }

        public byte[] KeyXOR(byte[] key, byte[] kiloChallenge)
        {
            byte[] keyXOR = new byte[32];
            int pos = 0;

            while (pos < 32)
            {
                keyXOR[pos] = (byte)(key[pos] ^ kiloChallenge[3]);
                keyXOR[pos + 1] = (byte)(key[pos + 1] ^ kiloChallenge[2]);
                keyXOR[pos + 2] = (byte)(key[pos + 2] ^ kiloChallenge[1]);
                keyXOR[pos + 3] = (byte)(key[pos + 3] ^ kiloChallenge[0]);

                pos += 4;
            }

            return keyXOR;
        }

        /// <summary>
        ///     EncryptKiloChallenge
        ///         1. Encryption Key
        ///         2. XOR Encryption Key With KiLo Challenge
        ///         3. AES Encryption Key
        /// </summary>
        /// <returns>byte[]</returns>
        public byte[] EncryptKiloChallenge()
        {
            byte[] plainTextBytes = new byte[16];

            for (int k = 0; k < 16; k++)
            {
                plainTextBytes[k] = (byte)k;
            }

            byte[] encryptionKey = this.KeyTransform(this._key);
            byte[] keyXOR = this.KeyXOR(encryptionKey, this.CovertStringHexToByte(this._kiloChallenge));
            byte[] encrypted;

            // Create an Aes object
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyXOR;
                encrypted = AESEncrypt(Encoding.ASCII.GetString(plainTextBytes), aesAlg.Key, aesAlg.IV);
            }

            return encrypted;
        }

        /// <summary>
        ///     Convert string hex to byte
        ///     Ex: "ace5b106" -> { 172, 229, 177, 06}
        /// </summary>
        /// <param name="str">string hex</param>
        /// <returns> byte[] </returns>
        private byte[] CovertStringHexToByte(string str)
        {
            byte[] result = Enumerable.Range(0, str.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(str.Substring(x, 2), 16))
                     .ToArray();

            return result;
        }

        /// <summary>
        ///     AES Encrypt
        /// </summary>
        /// <param name="plainText"> plainText </param>
        /// <param name="Key">Key</param>
        /// <param name="IV">IV</param>
        /// <returns>byte[]</returns>
        public byte[] AESEncrypt(string plainText, byte[] Key, byte[] IV)
        {

            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                //aesAlg.KeySize = 256; //[128 192 256]
                //aesAlg.BlockSize = 128;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.ECB;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            byte[] encrypt = new byte[16];
            for(int i=0; i<encrypt.Length; i++)
            {
                encrypt[i] = encrypted[i];
            }

            // Return the encrypted bytes from the memory stream.
            return encrypt;
        }

        public int CRC16(byte[] data)
        {
            int crc = 0xffff; //value: 65535
            foreach (byte b in data)
            {
                crc ^= b;
                for (int i = 0; i < 8; i++)
                {
                    if ((crc & 1) == 0)
                    {
                        crc >>= 1;
                    }
                    else
                    {
                        crc = (crc >> 1) ^ 0x8408; //value: 33800
                    }
                }
            }

            return crc ^ 0xffff; //value: 65535
        }

        public byte[] InvertDWORD(byte[] b)
        {
            for (int i = 0; i < b.Length; i++)
            {
                b[i] ^= 0xff; //value: 255
            }

            return b;
        }

        public void SetHeader(int offset, byte[] val)
        {
            if (val.Length != 4)
            {
                string message = string.Format("Header field requires a DWORD, got {0} {0}", val.GetType(), val);
                throw new Exception(message);
            }

            try
            {
                for (int i = 0; i < 4; i++)
                {
                    this._header[offset + i] = val[i];
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("SetHeader - Error: {0}", ex);
            }

        }

        public void AddHeader(byte[] b)
        {
            int length = this._header.Length + b.Length;
            byte[] newHeader = new byte[length];

            for (int i = 0; i < this._header.Length; i++)
            {
                newHeader[i] = this._header[i];
            }

            for (int i = 0; i < b.Length; i++)
            {
                newHeader[this._header.Length + i] = b[i];
            }

            this._header = newHeader;
        }

        public byte[] MakeRequest(string cmd, string[] args, byte[] body)
        {
            byte[] b = Encoding.ASCII.GetBytes(cmd);

            // Header: command, args, ... body size, header crc16, inverted command
            this._header = new byte[0x20]; //value: 32

            this.SetHeader(0, b);

            if (args.Length > 4)
            {
                throw new Exception("Header cannot have more than 4 arguments");
            }

            for (int i = 0; i < args.Length; i++)
            {
                byte[] arg = Encoding.ASCII.GetBytes(args[i]);
                this.SetHeader(4 * (i + 1), arg);
            }

            //// 0x14: body length
            byte[] crc16BodyLength = BitConverter.GetBytes((int)body.Length);
            this.SetHeader(0x14, crc16BodyLength); //value: 20

            ////0x1c: Inverted command
            this.SetHeader(0x1c, this.InvertDWORD(b)); //value: 28

            ////Header finished (with CRC placeholder), append body...
            AddHeader(body);

            ////finish with CRC for header and body
            byte[] crc16Header = BitConverter.GetBytes((int)this.CRC16(this._header));
            this.SetHeader(0x18, crc16Header); //value: 24

            return this._header;
        }
    }
}
