package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

public class JceTlsGostCredentialedDecryptor implements TlsCredentialedDecryptor
{

    protected JcaTlsCrypto crypto;
    protected Certificate certificate;
    protected PrivateKey privateKey;

    public JceTlsGostCredentialedDecryptor(JcaTlsCrypto crypto, Certificate certificate, PrivateKey privateKey)
    {
        if (crypto == null)
        {
            throw new IllegalArgumentException("'crypto' cannot be null");
        }
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }

        if (privateKey.getAlgorithm().contains("GOST"))
        {
            this.crypto = crypto;
            this.certificate = certificate;
            this.privateKey = privateKey;
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }
    }

    @Override
    public TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException
    {
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        byte[] sv = TlsUtils.generateSV(crypto, securityParameters, CryptoHashAlgorithm.gostr3411_2012_256);
        try
        {
            Cipher cipher = crypto.createGOSTEncryptionCipher("GostTransportK");
            cipher.init(Cipher.UNWRAP_MODE, privateKey, new IvParameterSpec(sv));
            SecretKey preMasterSecret = (SecretKey) cipher.unwrap(ciphertext, "MASTER_KEY", Cipher.SECRET_KEY);
            return new JceTlsSecretKey(crypto, preMasterSecret);
        } catch (GeneralSecurityException e)
        {
            throw new IOException(e);
        }
    }

    @Override
    public Certificate getCertificate()
    {
        return certificate;
    }

}
