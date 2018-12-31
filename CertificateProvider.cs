using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace tlstest
{
    public static class CertificateProvider
    {
        public const int KeySize = 4096;
        public const string SignatureAlgorithm = "SHA256WithRSA";

        public static X509Certificate2 GetOrCreateCertificate(String file, String subjectName)
        {
            byte[] data;
            if (File.Exists(file)) {
                data = File.ReadAllBytes(file);
            }
            else
            {
                data = GenerateSelfSignedCertificate(subjectName);

                Directory.CreateDirectory(Path.GetDirectoryName(file));

                SecureWrite.Write(file, stream =>
                {
                    stream.Write(data, 0, data.Length);
                });
            }

            return new X509Certificate2(data);
        }

        private static byte[] GenerateSelfSignedCertificate(string subjectName)
        {
            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);

            // Subject Public Key
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, KeySize);
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random));
            certificateGenerator.SetSignatureAlgorithm(SignatureAlgorithm);
            certificateGenerator.SetIssuerDN(new X509Name(subjectName));
            certificateGenerator.SetSubjectDN(new X509Name(subjectName));
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date);
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth));
            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            Org.BouncyCastle.X509.X509Certificate cert = certificateGenerator.Generate(subjectKeyPair.Private, random);
            Pkcs12Store store = new Pkcs12StoreBuilder().SetUseDerEncoding(true).Build();
            store.SetKeyEntry("unused", new AsymmetricKeyEntry(subjectKeyPair.Private), new X509CertificateEntry[] { new X509CertificateEntry(cert) });
            using (MemoryStream stream = new MemoryStream())
            {
                store.Save(stream, new char[0], random);
                return stream.ToArray();
            }
        }
    }
}