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
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ 0 };
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
    }

    public void generateClientKeyExchange(OutputStream output)
        throws IOException
    {
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
    }

    public TlsSecret generatePreMasterSecret()
        throws IOException
    {
        return null;

    }
}
