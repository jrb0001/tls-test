using System;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using OpenRA;

namespace tlstest
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            X509Certificate2 certificate = CreateCertificate();

            Thread serverThread = new Thread(new ThreadStart(new TestServer(certificate).Run));
            Thread clientThread = new Thread(new ThreadStart(new TestClient(certificate).Run));
            serverThread.Start();
            Thread.Sleep(100);
            clientThread.Start();
        }

        static X509Certificate2 CreateCertificate()
        {
            return CertificateProvider.GetOrCreateCertificate(Platform.SupportDir + "/certificate.p12", "CN=test");
        }
    }
}
