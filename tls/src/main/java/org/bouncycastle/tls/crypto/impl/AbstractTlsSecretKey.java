package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.crypto.TlsEncryptor;

import javax.crypto.SecretKey;
import java.io.IOException;

public abstract class AbstractTlsSecretKey extends AbstractTlsSecret {

    private final SecretKey secretKey;

    /**
     * Base constructor.
     *
     * @param secretKey the secret key.
     */
    protected AbstractTlsSecretKey(SecretKey secretKey) {
        super(new byte[0]);
        this.secretKey = secretKey;
    }

    @Override
    public synchronized byte[] encrypt(TlsEncryptor encryptor) throws IOException
    {
        checkAlive();
        return encryptor.wrap(secretKey);
    }

}
