using System;
using System.Net;
using System.Net.Sockets;  
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Authentication;

namespace tlstest
{
    public class TestServer
    {
        TcpListener server;
        X509Certificate2 certificate;

        public TestServer(X509Certificate2 certificate)
        {
            server = new TcpListener(IPAddress.Parse("::1"), 54376);
            this.certificate = certificate;
        }

        public void Run()
        {
            server.Start();
            TcpClient socket = server.AcceptTcpClient();
            SslStream tls = new SslStream(socket.GetStream(), true, HandleRemoteCertificateValidationCallback);
            tls.AuthenticateAsServer(certificate, true, SslProtocols.Tls12, false);

            tls.Write(Encoding.UTF8.GetBytes("Hello "));

            byte[] buffer = new byte[1024];
            int count = tls.Read(buffer, 0, buffer.Length);
            Console.Write(Encoding.UTF8.GetString(buffer, 0, count));

            socket.Close();
        }

        bool HandleRemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("TestServer");
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
    }
}
