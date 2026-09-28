package org.bouncycastle.tls.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.JCSPECDSA;
import ru.CryptoPro.JCSP.JCSPRSA;

import org.bouncycastle.util.Strings;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS client.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS client.
 * </p>
 */
public class GostDTLSServerTest
{
    public static void main(String[] args)
            throws Exception
    {
        boolean clientAuth = false;
        String recvString = "Hello World!\n";
        int port = 12443;
        int cipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384;
        // int cipherSuite = CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC;
        System.out.println("args: " + Arrays.toString(args));
        for (String arg : args)
        {
            int sep = arg.indexOf("=");
            switch(sep >= 0 ? arg.substring(0, sep) : arg)
            {
                case "--clientAuth": clientAuth = true; break;
                case "--recvString": recvString = arg.substring(sep + 1); break;
                case "--port": port = Integer.parseInt(arg.substring(sep + 1)); break;
                case "--cipherSuite": cipherSuite = Integer.parseInt(arg.substring(sep + 1), 16); break;
                default: throw new Exception("Unknown argument: " + arg);
            }
        }

        boolean sent = false;
        boolean successful = false;

        //----
        System.setProperty("enable_rsa_inverted_byte_order", "true"); // только для иностранной сюиты
        long start = System.currentTimeMillis();
        // С более высоким приоритетом - Java CSP.
        Security.insertProviderAt(new JCSP(), 1);
        Security.insertProviderAt(new JCSPRSA(), 2);
        Security.insertProviderAt(new JCSPECDSA(), 3);
        Security.insertProviderAt(new BouncyCastleProvider(), 4);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 5);
        long end = System.currentTimeMillis();
        System.out.println("Registration: " + (end - start) + " ms.");
        //----

        try {

            // while (true) {

            System.out.println("Starting...");

            // int port = 12443;
            final int mtu = 1500;

            //---- Используем системный провайдер вместо BC.
            class MyTlsCrypto extends JcaTlsCrypto
            {
                protected MyTlsCrypto()
                {
                    super(new DefaultJcaJceHelper(), new SecureRandom(), new SecureRandom());
                }
            }
            //----

            //TlsCrypto serverCrypto = new BcTlsCrypto();
            // Используем системный провайдер вместо BC.
            TlsCrypto serverCrypto = new MyTlsCrypto();

            DTLSVerifier verifier = new DTLSVerifier(serverCrypto);
            DTLSRequest request = null;

            byte[] data = new byte[mtu];
            final DatagramPacket packet = new DatagramPacket(data, mtu);

            final DatagramSocket socket = new DatagramSocket(port);
            System.out.println(socket);

            ByteArrayOutputStream out = new ByteArrayOutputStream(); // my

            try {

                //
                // Process incoming packets, replying with HelloVerifyRequest, until one is verified.
                //
                do {

                    System.out.println("Waiting packet...");
                    socket.receive(packet);

                    System.out.println("Verifying request...");
                    request = verifier.verifyRequest(packet.getAddress().getAddress(), data, 0, packet.getLength(), new DatagramSender()
                    {
                        public int getSendLimit() throws IOException
                        {
                            return mtu - 28;
                        }

                        public void send(byte[] buf, int off, int len) throws IOException
                        {
                            if (len > getSendLimit())
                            {
                                throw new TlsFatalAlert(AlertDescription.internal_error);
                            }

                            socket.send(new DatagramPacket(buf, off, len, packet.getAddress(), packet.getPort()));
                        }
                    });
                }
                while (null == request);

                //
                // Proceed to a handshake, passing verified 'request' (ClientHello) to DTLSServerProtocol.accept.
                //
                System.out.println("Accepting connection from " + packet.getAddress().getHostAddress() + ":" + packet.getPort());
                socket.connect(packet.getAddress(), packet.getPort());

                DatagramTransport transport = new UDPTransport(socket, mtu);

                // Uncomment to see packets
                // transport = new LoggingDatagramTransport(transport, System.out);

                GostMockDTLSServer server = new GostMockDTLSServer(serverCrypto, clientAuth, cipherSuite);
                DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

                DTLSTransport dtlsServer = serverProtocol.accept(server, transport, request);

                try
                {

                    byte[] buf = new byte[dtlsServer.getReceiveLimit()];

                    while (!socket.isClosed())
                    {
                        try
                        {
                            System.out.println("Receiving data...");
                            int length = dtlsServer.receive(buf, 0, buf.length, 60000);
                            if (length >= 0) {
                                out.write(buf, 0, length); // my
                                System.out.write(buf, 0, length);
                                System.out.println("Sending data "  + new String(buf, 0, length) + "...");
                                dtlsServer.send(buf, 0, length);
                                sent = true;
                            }
                        } catch (SocketTimeoutException ste)
                        {
                            ste.printStackTrace();
                        }
                    }
                    System.out.println("Stop processing.");
                    successful = true;
                } catch (Exception e)
                {
                    if (e instanceof SocketException && sent)
                    {
                        successful = true;
                    }
                    e.printStackTrace();
                } finally
                {
                    dtlsServer.close();
                    transport.close();
                }

            } catch (Exception e)
            {
                e.printStackTrace();
            } finally {
                socket.close();
            }

            if (!successful)
            {
                throw new Exception("Server failed.");
            }
            else {
                if (!Arrays.equals(Strings.toUTF8ByteArray(recvString), out.toByteArray()))
                {
                    throw new Exception("Received data is invalid.");
                }
            }

            // System.out.println("Pause...");
            // Thread.sleep(5000);

            // }

        } finally
        {

        }

    }
}
