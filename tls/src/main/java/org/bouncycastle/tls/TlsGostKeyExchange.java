package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsSecret;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * (D)TLS GOST key exchange.
 */
public class TlsGostKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        System.out.println("checkKeyExchange not implemented.");
        switch (keyExchange)
        {
            case KeyExchangeAlgorithm.GOSTR341112_256:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsCredentialedDecryptor serverCredentials = null;
    protected TlsEncryptor serverEncryptor;
    protected TlsSecret preMasterSecret;

    public TlsGostKeyExchange(int keyExchange)
    {
        super(checkKeyExchange(keyExchange));
    }

    public void skipServerCredentials()
        throws IOException
    {
        System.out.println("skipServerCredentials not implemented.");
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        System.out.println("processServerCredentials not implemented.");
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        System.out.println("processServerCertificate not implemented.");
    }

    public short[] getClientCertificateTypes()
    {
        System.out.println("getClientCertificateTypes not implemented.");
        return new short[]{ 0 };
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        System.out.println("processClientCredentials not implemented.");
    }

    public void generateClientKeyExchange(OutputStream output)
        throws IOException
    {
        System.out.println("generateClientKeyExchange not implemented.");
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
        System.out.println("processClientKeyExchange not implemented.");
    }

    public TlsSecret generatePreMasterSecret()
        throws IOException
    {
        System.out.println("generatePreMasterSecret not implemented.");
        return null;
    }

}
