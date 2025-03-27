package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.TlsUtils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class JceTlsGostHMAC extends JceTlsHMAC
{

    protected final JcaTlsCrypto crypto;
    private JceTlsSecretKey baseKey;
    private long seqNo = 0;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public JceTlsGostHMAC(JcaTlsCrypto crypto, int cryptoHashAlgorithm, Mac hmac, String algorithm)
    {
        super(cryptoHashAlgorithm, hmac, algorithm);
        this.crypto = crypto;
    }

    @Override
    public void setKey(byte[] key, int keyOff, int keyLen) {}

    @Override
    public void update(byte[] input, int inOff, int length)
    {
        // accumulate data because rekeying is needed
        buffer.write(input, inOff, length);
    }

    public void setBaseKey(JceTlsSecretKey secretKey)
    {
        this.baseKey = secretKey;
    }

    private void clean()
    {
        buffer = new ByteArrayOutputStream();
    }

    private void checkSequenceNumberLimit(long seqNo) throws GeneralSecurityException
    {
        if (seqNo >= 0x00001fffffffffffL)
        {
            throw new GeneralSecurityException("Sequence number extremely close to overflow (2^44-1 packets).");
        }
    }

    private void reKeying(long seqNo) throws GeneralSecurityException
    {
        checkSequenceNumberLimit(seqNo);
        try
        {
            String algorithm = "GOST3412_2015_K";
            SecretKeyFactory secretKeyFactory = crypto.getHelper().createSecretKeyFactory(algorithm + "_TLS_DERIVED_MAC_KEY");
            secretKeyFactory.generateSecret(new SecretKeySpec(TlsUtils.longToByteArray(seqNo), "SEQ_NO")); // 1. pass the sequence number
            SecretKey key = secretKeyFactory.translateKey(baseKey.getSecretKey()); // 2. derive a new key from key tree
            hmac.init(key); // mac size is 16
            this.seqNo = seqNo;
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e)
        {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public byte[] calculateMAC(long seqNo)
    {
        try
        {
            reKeying(seqNo);
            byte[] data = buffer.toByteArray();
            clean();
            super.update(data, 0, data.length);
            return super.calculateMAC();
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override
    public void calculateMAC(long seqNo, byte[] output, int outOff)
    {
        try
        {
            reKeying(seqNo);
            byte[] data = buffer.toByteArray();
            clean();
            super.update(data, 0, data.length);
            super.calculateMAC(output, outOff);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override
    public void reset()
    {
        clean();
        super.reset();
    }

}
