package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.*;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;

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

    protected TlsEncryptor encryptor;
    protected TlsSecret preMasterSecret;

    protected TlsCredentialedSigner serverCredentials = null;
    protected Certificate serverCertificate = null;

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
        this.serverCredentials = TlsUtils.requireSignerCredentials(serverCredentials);
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        this.serverCertificate = serverCertificate;
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ ClientCertificateType.gost_sign256 };
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        System.out.println("processClientCredentials not implemented.");
    }

    public void generateClientKeyExchange(OutputStream output)
        throws IOException
    {
        byte[] sv = generateSV();
        TlsCertificate tlsCertificate = serverCertificate.getCertificateAt(0);
        this.encryptor = tlsCertificate.createEncryptor(TlsCertificateRole.GOST_ENCRYPTION, keyExchange, new IvParameterSpec(sv));
        // Exports key as GostR3410_GostR3412_KeyTransport.
        this.preMasterSecret = TlsUtils.generateEncryptedGOSTPreMasterSecret(context, encryptor, output);
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

    private byte[] generateSV() {
        TlsHash hash = context.getCrypto().createHash(CryptoHashAlgorithm.gostr3411_2012_256);
        byte[] clientRandom = context.getSecurityParameters().getClientRandom();
        byte[] serverRandom = context.getSecurityParameters().getServerRandom();
        hash.update(clientRandom, 0, clientRandom.length);
        hash.update(serverRandom, 0, serverRandom.length);
        return hash.calculateHash(); // 32 bytes
    }

}
