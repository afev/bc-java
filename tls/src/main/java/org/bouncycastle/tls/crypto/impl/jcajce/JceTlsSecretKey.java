package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecretKey;

import javax.crypto.SecretKey;

public class JceTlsSecretKey
    extends AbstractTlsSecretKey {

    protected final JcaTlsCrypto crypto;

    public JceTlsSecretKey(JcaTlsCrypto crypto, SecretKey key)
    {
        super(key);

        this.crypto = crypto;
    }

    @Override
    protected AbstractTlsCrypto getCrypto() {
        return crypto;
    }

    @Override
    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length) {
        return null;
    }

    @Override
    public synchronized TlsSecret hkdfExpand(int cryptoHashAlgorithm, byte[] info, int length) {
        return null;
    }

    @Override
    public synchronized TlsSecret hkdfExtract(int cryptoHashAlgorithm, TlsSecret ikm) {
        return null;
    }

}
