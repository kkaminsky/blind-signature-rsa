using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace BlindSignRSA
{
    class Program
    {
        static void Main(string[] args)
        {

            
            BlindRSA rsa = new BlindRSA();
            string message = "Hello world!";
            Console.WriteLine("message: " + message);
            BigInteger bigIntFromMessageOrX = new BigInteger(Encoding.ASCII.GetBytes(message));
            
            Console.WriteLine("x: " + bigIntFromMessageOrX);
          
            BigInteger encryptedTextOrY = rsa.EncryptWithBlindingFactor(bigIntFromMessageOrX);
            Console.WriteLine("y: " + encryptedTextOrY);

            BigInteger signForEncryptedTextOrZ = rsa.Sign(encryptedTextOrY);
            Console.WriteLine("z: " + signForEncryptedTextOrZ);

            BigInteger signForDecryptedTextOrS = rsa.ClearBlindingFactor(signForEncryptedTextOrZ);
            Console.WriteLine("s: " + signForDecryptedTextOrS);

            BigInteger textFromSign = rsa.Verification(signForDecryptedTextOrS);
            Console.WriteLine("sign: " + textFromSign);
            Console.WriteLine("textFromSign: " + Encoding.ASCII.GetString(textFromSign.ToByteArray()));

            if (Encoding.ASCII.GetString(textFromSign.ToByteArray()) == message)
                Console.WriteLine("True sign");
            else
                Console.WriteLine("False sign");

            Console.ReadLine();
        }
    }

    class BlindRSA
    {
        public BigInteger n;
        private BigInteger p;
        private BigInteger q;
        private BigInteger d;
        public BigInteger e;
        private BigInteger k;
        public BlindRSA()
        {
            p = BigInteger.ProbablePrime(256, new Random());
            q = BigInteger.ProbablePrime(256, new Random());
            n = p.Multiply(q); // модуль
            e = n; // открытый ключ для проверки подписи Боба
            k = n; // секретный ключ Алисы в данной системе
            BigInteger q_1 = q.Subtract(BigInteger.One);
            BigInteger p_1 = p.Subtract(BigInteger.One);
            while (e.CompareTo(q_1.Multiply(p_1)) != -1 && e.Gcd(q_1.Multiply(p_1)) != BigInteger.One)
            {
                e = BigInteger.ProbablePrime(256, new Random());
            }
            while (k.CompareTo(q_1.Multiply(p_1)) != -1 && k.Gcd(q_1.Multiply(p_1)) != BigInteger.One)
            {
                k = BigInteger.ProbablePrime(256, new Random());
            }
            d = e.ModInverse(q_1.Multiply(p_1)); // секретный ключ Боба для создании подписи
        }
        public BigInteger EncryptWithBlindingFactor(BigInteger message)
        {
            return message.Multiply(k.ModPow(e, n)); // y = x*(k^e) - зашифрованное сообщение
        }
        public BigInteger Sign(BigInteger message)
        {
            return message.ModPow(d, n); // z = y^d = (x*k^e)^d = x^d * k^(e*d) = k*x^d - подпись для зашифрованного сообщения
        }
        
        public BigInteger ClearBlindingFactor(BigInteger message)
        {
            return message.Multiply(k.ModInverse(n)).Mod(n); // s = z*k^-1 = (k*x^d) * k^-1 = x^d - подпись для исходного сообщения
        }
        public BigInteger Verification(BigInteger sign)
        {
            return sign.ModPow(e, n); // x = s^e = (x^d)^e - если подпись подлинная, то получим исходное сообщение
        }


    }
}
