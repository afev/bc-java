package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

public class JcaTlsGOSTVerifier implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;
    private final String algorithmName;

    public JcaTlsGOSTVerifier(JcaTlsCrypto crypto, PublicKey publicKey, int signatureScheme, String algorithmName)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.signatureScheme = signatureScheme;
        this.algorithmName = algorithmName;
    }

    @Override
    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException
    {
        return null;
    }

    @Override
    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();

        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        try
        {
            Signature verifier = crypto.getHelper().createSignature(algorithmName);
            verifier.initVerify(publicKey);
            verifier.update(hash, 0, hash.length);
            byte[] signature = TlsUtils.inverse(digitallySigned.getSignature());
            return verifier.verify(signature);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

}
