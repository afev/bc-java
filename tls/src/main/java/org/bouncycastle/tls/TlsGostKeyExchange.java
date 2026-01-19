package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.*;

import javax.crypto.spec.IvParameterSpec;
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

    protected TlsEncryptor encryptor;
    protected TlsSecret preMasterSecret;

    protected TlsCredentialedDecryptor serverCredentials = null;
    protected Certificate serverCertificate = null;

    public TlsGostKeyExchange(int keyExchange)
    {
        super(checkKeyExchange(keyExchange));
    }

    public void skipServerCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        this.serverCredentials = TlsUtils.requireDecryptorCredentials(serverCredentials);
        this.serverCertificate = this.serverCredentials.getCertificate();
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        this.serverCertificate = serverCertificate;
    }

    public short[] getClientCertificateTypes()
    {
        return new short[] {ClientCertificateType.gost_sign256};
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        TlsUtils.requireSignerCredentials(clientCredentials);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        byte[] sv = TlsUtils.generateSV(context.getCrypto(), context.getSecurityParametersHandshake(), CryptoHashAlgorithm.gostr3411_2012_256);
        TlsCertificate tlsCertificate = serverCertificate.getCertificateAt(0);
        this.encryptor = tlsCertificate.createEncryptor(TlsCertificateRole.GOST_ENCRYPTION, keyExchange, new IvParameterSpec(sv));
        // Exports key as GostR3410_GostR3412_KeyTransport.
        this.preMasterSecret = TlsUtils.generateEncryptedGOSTPreMasterSecret(context, encryptor, output);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        // ASN.1 encoded data, opaque is not needed.
        byte[] encryptedPreMasterSecret = SSL3Utils.readEncryptedPMS(input);
        this.preMasterSecret = serverCredentials.decrypt(new TlsCryptoParameters(context), encryptedPreMasterSecret);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        TlsSecret tmp = this.preMasterSecret;
        this.preMasterSecret = null;
        return tmp;
    }

}
