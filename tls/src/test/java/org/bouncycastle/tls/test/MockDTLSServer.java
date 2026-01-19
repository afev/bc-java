package org.bouncycastle.tls.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.jcajce.JceTlsGostCredentialedDecryptor;
import org.bouncycastle.util.encoders.Hex;
import ru.CryptoPro.JCP.KeyStore.StoreInputStream;

class MockDTLSServer
    extends DefaultTlsServer
{
    private boolean clientAuth;
    private int cipherSuite = 0;

    MockDTLSServer()
    {
        this(new BcTlsCrypto());
    }

    MockDTLSServer(TlsCrypto crypto)
    {
        this(crypto, false, 0);
    }

    MockDTLSServer(TlsCrypto crypto, boolean clientAuth, int cipherSuite)
    {
        super(crypto);
        this.clientAuth = clientAuth;
        this.cipherSuite = cipherSuite;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server raised alert: " + AlertLevel.getText(alertLevel)
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
        out.println("DTLS server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("DTLS server negotiated version " + serverVersion);

        return serverVersion;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        if (clientAuth) {
            short[] certificateTypes = new short[]{ClientCertificateType.rsa_sign,
                    ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign, ClientCertificateType.gost_sign256};

            Vector serverSigAlgs = null;
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion())) {
                serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
            }

            Vector certificateAuthorities = new Vector();
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-dsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-ecdsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-rsa.pem").getSubject());
            ///certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-gost.pem").getSubject());

            // All the CA certificates are currently configured with this subject
            // certificateAuthorities.addElement(new X500Name("CN=BouncyCastle TLS Test CA"));
            /// Издатель сертификата клиента.
            certificateAuthorities.addElement(new X500Name("CN=BC TLS Root,O=OOO Crypto-Pro,C=RU"));
            certificateAuthorities.addElement(new X500Name("C=RU,O=OOO Crypto-Pro,CN=BC TLS Root"));
            certificateAuthorities.addElement(new X500Name("CN=BC TLS RSA Root,O=OOO Crypto-Pro,C=RU"));
            certificateAuthorities.addElement(new X500Name("C=RU,O=OOO Crypto-Pro,CN=BC TLS RSA Root"));

            return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
        }
        return null;
    }

    public void notifyClientCertificate(org.bouncycastle.tls.Certificate clientCertificate) throws IOException
    {
        TlsCertificate[] chain = clientCertificate.getCertificateList();

        System.out.println("DTLS server received client certificate chain of length " + chain.length);
        for (int i = 0; i != chain.length; i++)
        {
            Certificate entry = Certificate.getInstance(chain[i].getEncoded());
            // TODO Create fingerprint based on certificate signature algorithm digest
            System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                + entry.getSubject() + ")");
        }

        boolean isEmpty = (clientCertificate == null || clientCertificate.isEmpty());

        if (isEmpty)
        {
            return;
        }

        // Клиентский сертификат x509-client-gost.pem в папке bc-java\tls\src\test\resources\org\bouncycastle\tls\test\.
        // Там же должен лежать корневой сертификат клиента в виде x509-ca-gost.pem.
        String[] trustedCertResources = new String[]{ /*"x509-client-dsa.pem", "x509-client-ecdh.pem",
            "x509-client-ecdsa.pem", "x509-client-ed25519.pem", "x509-client-ed448.pem", "x509-client-ml_dsa_44.pem",
            "x509-client-ml_dsa_65.pem", "x509-client-ml_dsa_87.pem", "x509-client-rsa_pss_256.pem",
            "x509-client-rsa_pss_384.pem", "x509-client-rsa_pss_512.pem",*/ "x509-client-rsa.pem", "x509-client-gost.pem" };

        TlsCertificate[] certPath = TlsTestUtils.getTrustedCertPath(context.getCrypto(), chain[0],
            trustedCertResources);

        if (null == certPath)
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        TlsUtils.checkPeerSigAlgs(context, certPath);
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null)
        {
            System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
        }

        byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

        byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
        System.out.println("Server 'tls-unique': " + hex(tlsUnique));
    }

    public void processClientExtensions(Hashtable clientExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getClientRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.processClientExtensions(clientExtensions);
    }

    public Hashtable getServerExtensions() throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return super.getServerExtensions();
    }

    public void getServerExtensionsForConnection(Hashtable serverExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.getServerExtensionsForConnection(serverExtensions);
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException
    {
        //return TlsTestUtils.loadEncryptionCredentials(context, new String[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" },
        //     "x509-server-key-rsa-enc.pem");
        // В случае подключения по TLS_RSA_WITH_AES_256_GCM_SHA384.
        try {
            KeyStore serverStore = KeyStore.getInstance("HDIMAGE", "JCSPRSA");
            serverStore.load(new StoreInputStream("bc_tls_server_rsa"), null);
            PrivateKey privateKey = (PrivateKey) serverStore.getKey("bc_tls_server_rsa", null);
            java.security.cert.Certificate certificate = serverStore.getCertificate("bc_tls_server_rsa");
            JcaTlsCertificate javaCert = new JcaTlsCertificate((JcaTlsCrypto) getCrypto(), certificate.getEncoded());
            org.bouncycastle.tls.Certificate bcCert = new org.bouncycastle.tls.Certificate(new TlsCertificate[] {javaCert});
            TlsCredentialedDecryptor decryptor = new JceDefaultTlsCredentialedDecryptor((JcaTlsCrypto) getCrypto(), bcCert, privateKey);
            return decryptor;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    protected TlsCredentialedDecryptor getGOSTEncryptionCredentials() throws IOException
    {
        // В случае подключения по TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC.
        try
        {
            JcaTlsCrypto crypto = (JcaTlsCrypto) context.getCrypto();
            // Trust store.
            // KeyStore trustStore = KeyStore.getInstance("JKS");
            // trustStore.load(null, null);
            // java.security.cert.Certificate opensslCert = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("c:\\Temp\\csptest\\root.cer"));
            // trustStore.setCertificateEntry("gost_server_root", opensslCert);
            // java.security.cert.Certificate clientRootCert = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("c:\\Temp\\csptest\\client_root.cer"));
            // trustStore.setCertificateEntry("gost_client_root", clientRootCert);
            // java.security.cert.Certificate testCaRoot = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("c:\\Temp\\csptest\\test_ca.cer"));
            // trustStore.setCertificateEntry("test_ca", testCaRoot);
            // java.security.cert.Certificate bcRoot = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("c:\\Temp\\csptest\\bc_tls_root.cer"));
            // trustStore.setCertificateEntry("bc_root", bcRoot);
            // Key store.
            KeyStore serverStore = KeyStore.getInstance("HDIMAGE", "JCSP");
            serverStore.load(new StoreInputStream("bc_tls_server"), null);
            PrivateKey privateKey = (PrivateKey) serverStore.getKey("bc_tls_server", null);
            java.security.cert.Certificate[] certificates = serverStore.getCertificateChain("bc_tls_server");
            X509Certificate[] x509Certs = new X509Certificate[certificates.length];
            System.arraycopy(certificates, 0, x509Certs, 0, certificates.length);
            TlsCertificate[] certificateList = new TlsCertificate[x509Certs.length];
            for (int i = 0; i < x509Certs.length; ++i)
            {
                certificateList[i] = new JcaTlsCertificate(crypto, x509Certs[i]);
            }
            org.bouncycastle.tls.Certificate bcCertificate = new org.bouncycastle.tls.Certificate(certificateList);
            return new JceTlsGostCredentialedDecryptor(crypto, bcCertificate, privateKey);
        }
        catch (Exception e)
        {
            throw new IOException(e);
        }
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
        return TlsTestUtils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.rsa);
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.only();
    }

    protected int[] getSupportedCipherSuites()
    {
        // Для тестов оставляем только одну сюиту.
        if (cipherSuite != 0)
        {
            return TlsUtils.getSupportedCipherSuites(getCrypto(), new int[]{cipherSuite});
        }
        return super.getSupportedCipherSuites();
    }
}
