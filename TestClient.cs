using System;
using System.Threading;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Text;
using System.Security.Authentication;

namespace tlstest
{
    public class TestClient
    {
        X509Certificate2 certificate;

        public TestClient(X509Certificate2 certificate)
        {
            this.certificate = certificate;
        }

        public void Run()
        {
            TcpClient socket = new TcpClient("::1", 54376);
            SslStream tls = new SslStream(socket.GetStream(), false, HandleRemoteCertificateValidationCallback, HandleLocalCertificateSelectionCallback);
            tls.AuthenticateAsClient("::1", new X509CertificateCollection(new X509Certificate[] { certificate }), SslProtocols.Tls12, false);

            byte[] buffer = new byte[1024];
            int count = tls.Read(buffer, 0, buffer.Length);
            Console.Write(Encoding.UTF8.GetString(buffer, 0, count));

            tls.Write(Encoding.UTF8.GetBytes("World!\n"));

            socket.Close();
        }

        bool HandleRemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("TestClient");
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }
            else
            {
                Console.WriteLine("Equals: " + certificate.Equals(this.certificate));
                if (certificate.Equals(this.certificate))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        X509Certificate HandleLocalCertificateSelectionCallback(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            Console.WriteLine("CertificateSelection");
            if (localCertificates.Count > 0)
            {
                return localCertificates[0];
            }
            else
            {
                return null;
            }
        }
    }
}
