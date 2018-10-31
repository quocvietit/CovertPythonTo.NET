using System;
using System.Linq;
using System.Text;

namespace CovertCode
{
    class Program
    {

        static void Main(string[] args)
        {
            try
            {
                //string key = "qndiakxxuiemdklseqid~a~niq,zjuxl";
                //string kiloChallenge = "ace5b106";
                
                string key = args[0];
                string kiloChallenge = args[1];

                Encrypt encrypt = new Encrypt(key, kiloChallenge);
                byte[] result = encrypt.EncryptKiloChallenge();

                string resultTest3 = string.Join(" ", result.Select(c => c.ToString("X2")).ToArray());
                Console.WriteLine("Encrypt: \n\t{0}", resultTest3);

                string[] arg = new string[] { "METR", "\x00\x00\x00\x00", "\x02\x00\x00\x00", "\x00\x00\x00\x00" };
                byte[] kiloRequest = encrypt.MakeRequest("KILO", arg, result);
                string kiloRequestHex = string.Join("", kiloRequest.Select(c => c.ToString("X2")).ToArray());

                Console.Write("Kilo Metr Request: \n\t");
                for (int i=0; i< kiloRequestHex.Length; i++)
                {
                    Console.Write(kiloRequestHex[i]);
                    if (i == 31 || i == 63)
                    {
                        Console.Write("\n\t");
                    }
                    else if(i%2 == 1 )
                    {
                        Console.Write(" ");
                    }
                }

                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex);
            }
        }
    }
}