package org.bouncycastle.tls.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Strings;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.JCSPECDSA;
import ru.CryptoPro.JCSP.JCSPRSA;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS server.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS server.
 * </p>
 */
public class DTLSClientTest
{
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args)
        throws Exception
    {
        String sendString = "Hello World!\n";
        InetAddress address = InetAddress.getLocalHost();
        int port = 12443;
        int cipherSuite = CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC; // CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384
        System.out.println("args: " + Arrays.toString(args));
        for (String arg : args)
        {
            int sep = arg.indexOf("=");
            switch(sep >= 0 ? arg.substring(0, sep) : arg)
            {
                case "--sendString": sendString = arg.substring(sep + 1); break;
                case "--address": address = InetAddress.getByName(arg.substring(sep + 1)); break;
                case "--port": port = Integer.parseInt(arg.substring(sep + 1)); break;
                case "--cipherSuite": cipherSuite = Integer.parseInt(arg.substring(sep + 1), 16); break;
                default: throw new Exception("Unknown argument: " + arg);
            }
        }

        System.out.println("Connection to " + address.getHostAddress() + ":" + port + "...");
        //----
        System.setProperty("enable_rsa_inverted_byte_order", "true"); // только для иностранной сюиты
        long start = System.currentTimeMillis();
        Security.insertProviderAt(new JCSP(), 1);
        Security.insertProviderAt(new JCSPRSA(), 2);
        Security.insertProviderAt(new JCSPECDSA(), 3);
        Security.insertProviderAt(new BouncyCastleProvider(), 4);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 5);
        long end = System.currentTimeMillis();
        System.out.println("Registration: " + (end - start) + " ms.");
        //----

        // InetAddress address = InetAddress.getLocalHost();
        // InetAddress address = InetAddress.getByName("192.168.63.92"); // ubuntu
        // InetAddress address = InetAddress.getByName("192.168.63.51"); // me
        // int port = 12443;

        // Не используем, так как внутри вызовется BC.
        // TlsSession session = createSession(address, port);

        //---- Используем системный провайдер вместо BC.
        class MyTlsCrypto extends JcaTlsCrypto
        {
            protected MyTlsCrypto()
            {
                super(new DefaultJcaJceHelper(), new SecureRandom(), new SecureRandom());
            }
        }
        //----

        // MockDTLSClient client = new MockDTLSClient(new MyTlsCrypto(), session);
        MockDTLSClient client = new MockDTLSClient(new MyTlsCrypto(), null, cipherSuite);

        DTLSTransport dtls = openDTLSConnection(address, port, client);

        System.out.println("Receive limit: " + dtls.getReceiveLimit());
        System.out.println("Send limit: " + dtls.getSendLimit());

        // Send and hopefully receive a packet back

        byte[] request = Strings.toUTF8ByteArray(sendString);
        dtls.send(request, 0, request.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream(); // my

        byte[] response = new byte[dtls.getReceiveLimit()];
        int received = dtls.receive(response, 0, response.length, 30000);
        if (received >= 0)
        {
            out.write(response, 0, received);
            System.out.println(new String(response, 0, received, "UTF-8"));
        }

        dtls.close();

        if (!Arrays.equals(request, out.toByteArray()))
        {
            throw new Exception("Received data is invalid.");
        }
    }

    private static TlsSession createSession(InetAddress address, int port)
        throws IOException
    {
        MockDTLSClient client = new MockDTLSClient(null); // будет использован BC
        DTLSTransport dtls = openDTLSConnection(address, port, client);
        TlsSession session = client.getSessionToResume();
        dtls.close();
        return session;
    }

    private static DTLSTransport openDTLSConnection(InetAddress address, int port, TlsClient client)
        throws IOException
    {
        System.out.println("Open DLTS connection...");
        DatagramSocket socket = new DatagramSocket();
        socket.connect(address, port);

        int mtu = 1500;
        DatagramTransport transport = new UDPTransport(socket, mtu);
        transport = new UnreliableDatagramTransport(transport, secureRandom, 0, 0);
        // transport = new LoggingDatagramTransport(transport, System.out);

        DTLSClientProtocol protocol = new DTLSClientProtocol();
        System.out.println("Connect...");
        return protocol.connect(client, transport);
    }
}
