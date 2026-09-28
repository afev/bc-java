package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import ru.CryptoPro.JCP.KeyStore.StoreInputStream;

class GostMockDTLSClient
        extends DefaultTlsClient
{
    TlsSession session;

    private int handshakeTimeoutMillis = 0;

    private int cipherSuite = 0;

    GostMockDTLSClient(TlsSession session)
    {
        super(new BcTlsCrypto());

        this.session = session;
    }

    GostMockDTLSClient(TlsCrypto crypto, TlsSession session)
    {
        super(crypto);

        this.session = session;
    }

    GostMockDTLSClient(TlsCrypto crypto, TlsSession session, int cipherSuite)
    {
        super(crypto);

        this.session = session;
        this.cipherSuite = cipherSuite;
    }

    public TlsSession getSessionToResume()
    {
        return this.session;
    }

    public int getHandshakeTimeoutMillis()
    {
        return handshakeTimeoutMillis;
    }

    public void setHandshakeTimeoutMillis(int millis)
    {
        handshakeTimeoutMillis = millis;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS client raised alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS client received alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);

        System.out.println("DTLS client negotiated version " + serverVersion);
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                TlsCertificate[] chain = serverCertificate.getCertificate().getCertificateList();

                System.out.println("DTLS client received server certificate chain of length " + chain.length);
                for (int i = 0; i != chain.length; i++)
                {
                    Certificate entry = Certificate.getInstance(chain[i].getEncoded());
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                }

                boolean isEmpty = serverCertificate == null || serverCertificate.getCertificate() == null
                        || serverCertificate.getCertificate().isEmpty();

                if (isEmpty)
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                String[] trustedCertResources = new String[]{ "x509-server-rsa2.pem", "x509-server-gost.pem" };

                TlsCertificate[] certPath = TlsTestUtils.getTrustedCertPath(context.getCrypto(), chain[0],
                        trustedCertResources);

                if (null == certPath)
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                TlsUtils.checkPeerSigAlgs(context, certPath);
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException
            {
                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (certificateTypes == null || !(Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign) || Arrays.contains(certificateTypes, ClientCertificateType.gost_sign256)))
                {
                    return null;
                }
                // return TlsTestUtils.loadSignerCredentials(context, certificateRequest.getSupportedSignatureAlgorithms(),
                //     SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");
                TlsCrypto crypto = context.getCrypto();
                TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);
                PrivateKey privateKey;
                java.security.cert.Certificate[] certificates;
                SignatureAndHashAlgorithm signatureAndHashAlgorithm;
                int actualCipherSuite = cryptoParams.getSecurityParametersHandshake().getCipherSuite();
                System.out.println("Require client credentials for cipher suite " + actualCipherSuite);
                if (actualCipherSuite == CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC)
                {
                    try {
                        KeyStore clientStore = KeyStore.getInstance("HDIMAGE", "JCSP");
                        clientStore.load(new StoreInputStream("bc_tls_client"), null);
                        privateKey = (PrivateKey) clientStore.getKey("bc_tls_client", null);
                        certificates = clientStore.getCertificateChain("bc_tls_client");
                        signatureAndHashAlgorithm = SignatureAndHashAlgorithm.gostr34102012_256;
                    } catch (Exception e) {
                        throw new IOException(e);
                    }
                }
                else
                {
                    try {
                        KeyStore clientStore = KeyStore.getInstance("HDIMAGE", "JCSPRSA");
                        clientStore.load(new StoreInputStream("bc_tls_client_rsa"), null);
                        privateKey = (PrivateKey) clientStore.getKey("bc_tls_client_rsa", null);
                        certificates = clientStore.getCertificateChain("bc_tls_client_rsa");
                        signatureAndHashAlgorithm = SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha1, SignatureAlgorithm.rsa);
                    } catch (Exception e) {
                        throw new IOException(e);
                    }
                }
                X509Certificate[] x509Certs = new X509Certificate[certificates.length];
                System.arraycopy(certificates, 0, x509Certs, 0, certificates.length);
                TlsCertificate[] certificateList = new TlsCertificate[x509Certs.length];
                for (int i = 0; i < x509Certs.length; ++i)
                {
                    certificateList[i] = new JcaTlsCertificate((JcaTlsCrypto)crypto, x509Certs[i]);
                }
                org.bouncycastle.tls.Certificate bcCertificate = new org.bouncycastle.tls.Certificate(certificateList);
                return new JcaDefaultTlsCredentialedSigner(cryptoParams, (JcaTlsCrypto)crypto, privateKey, bcCertificate, signatureAndHashAlgorithm);
            }
        };
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null)
        {
            System.out.println("Client ALPN: " + protocolName.getUtf8Decoding());
        }

        TlsSession newSession = context.getSession();
        if (newSession != null)
        {
            if (newSession.isResumable())
            {
                byte[] newSessionID = newSession.getSessionID();
                String hex = hex(newSessionID);

                if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
                {
                    System.out.println("Client resumed session: " + hex);
                }
                else
                {
                    System.out.println("Client established session: " + hex);
                }

                this.session = newSession;
            }

            byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
            if (null != tlsServerEndPoint)
            {
                System.out.println("Client 'tls-server-end-point': " + hex(tlsServerEndPoint));
            }

            byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
            System.out.println("Client 'tls-unique': " + hex(tlsUnique));
        }
    }

    public Hashtable getClientExtensions() throws IOException
    {
        if (context.getSecurityParametersHandshake().getClientRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return super.getClientExtensions();
    }

    public void processServerExtensions(Hashtable serverExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.processServerExtensions(serverExtensions);
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.only();
    }

    protected int[] getSupportedCipherSuites() {
        // Для тестов оставляем только одну сюиту.
        if (cipherSuite != 0) {
            return new int[] {cipherSuite};
        }
        return super.getSupportedCipherSuites();
    }

}
