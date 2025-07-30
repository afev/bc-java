package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsEncryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public final class JcaTlsGOSTEncryptor
    implements TlsEncryptor
{

    private final JcaTlsCrypto crypto;
    private final PublicKey pubKey;
    private final String cipherName;
    private final AlgorithmParameterSpec cipherParams;

    JcaTlsGOSTEncryptor(JcaTlsCrypto crypto, PublicKey pubKey, String cipherName, AlgorithmParameterSpec cipherParams)
    {
        this.crypto = crypto;
        this.pubKey = pubKey;
        this.cipherName = cipherName;
        this.cipherParams = cipherParams;
    }

    @Override
    public byte[] encrypt(byte[] input, int inOff, int length) throws IOException
    {
        throw new IOException("Encrypt is unsupported.");
    }

    @Override
    public byte[] wrap(SecretKey secretKey) throws IOException
    {
        try
        {
            Cipher c = crypto.createGOSTEncryptionCipher(cipherName);
            c.init(Cipher.WRAP_MODE, pubKey, cipherParams);
            return c.wrap(secretKey);
        }
        catch (GeneralSecurityException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }


}
