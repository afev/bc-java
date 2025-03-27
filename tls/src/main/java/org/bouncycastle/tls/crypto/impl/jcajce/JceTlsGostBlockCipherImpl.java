package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.TlsUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class JceTlsGostBlockCipherImpl extends JceBlockCipherImpl
{

    private JceTlsSecretKey baseKey;
    private byte[] cipherIv;
    private long seqNo = 0;

    public JceTlsGostBlockCipherImpl(JcaTlsCrypto crypto, Cipher cipher, String algorithm, int keySize, boolean isEncrypting) throws GeneralSecurityException
    {
        super(crypto, cipher, algorithm, keySize, isEncrypting);
    }

    @Override
    public void setKey(byte[] key, int keyOff, int keyLen) {}

    @Override
    public void init(byte[] iv, int ivOff, int ivLen)
    {
        if (cipherIv != null)
        {
            throw new IllegalStateException("IV is already set.");
        }
        byte[] tmpIv = TlsUtils.copyOfRangeExact(iv, ivOff, ivOff + ivLen);
        if (tmpIv.length != 8)
        {
            throw new IllegalStateException("Invalid IV length: " + tmpIv.length);
        }
        cipherIv = tmpIv;
   }

    public void setBaseKey(JceTlsSecretKey secretKey)
    {
        this.baseKey = secretKey;
    }

    private void reKeying(long seqNo) throws GeneralSecurityException
    {
        try
        {
            String algorithm = "GOST3412_2015_K";
            SecretKeyFactory secretKeyFactory = crypto.getHelper().createSecretKeyFactory(algorithm + "_TLS_DERIVED_CIPHER_KEY");
            secretKeyFactory.generateSecret(new SecretKeySpec(TlsUtils.longToByteArray(seqNo), "SEQ_NO")); // 1. pass the sequence number
            SecretKey key = secretKeyFactory.translateKey(baseKey.getSecretKey()); // 2. derive a new key from key tree
            if (seqNo != this.seqNo)
            {
                TlsUtils.increaseBlockByOne(cipherIv, cipherIv.length - 1); // increase IV by 1 per record
            }
            cipher.init(cipherMode, key, new IvParameterSpec(cipherIv));
            this.seqNo = seqNo;
        }
        catch (NoSuchAlgorithmException|NoSuchProviderException e)
        {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public int doFinal(long seqNo, byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
    {
        try
        {
            reKeying(seqNo);
            return super.doFinal(input, inputOffset, inputLength, output, outputOffset);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

}
