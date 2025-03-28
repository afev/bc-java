package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.*;

import java.io.IOException;

public class TlsGostBlockCipher implements TlsCipher
{

    private final TlsCryptoParameters cryptoParams;
    private final byte[] randomData;
    private final TlsBlockCipherImpl decryptCipher, encryptCipher;
    private final TlsSuiteMac readMac, writeMac;

    public TlsGostBlockCipher(TlsCryptoParameters cryptoParams, TlsBlockCipherImpl encryptCipher,
        TlsBlockCipherImpl decryptCipher, TlsHMAC clientMac, TlsHMAC serverMac, int cipherKeySize)
        throws IOException
    {
        this.cryptoParams = cryptoParams;
        this.randomData = cryptoParams.getNonceGenerator().generateNonce(256);

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        // Mac does not depend on client/server side now, read/write tag has been passed in JceTlsSecretKey#generateKeyForTls.
        this.writeMac = new TlsSuiteHMac(cryptoParams, clientMac);
        this.readMac = new TlsSuiteHMac(cryptoParams, serverMac);

    }

    @Override
    public int getCiphertextDecodeLimit(int plaintextLimit)
    {
        int macSize = readMac.getSize();
        int innerPlaintextLimit = plaintextLimit;
        return getCiphertextLength(macSize, innerPlaintextLimit);
    }

    @Override
    public int getCiphertextEncodeLimit(int plaintextLimit)
    {
        int macSize = writeMac.getSize();
        int innerPlaintextLimit = plaintextLimit;
        return getCiphertextLength(macSize, innerPlaintextLimit);
    }

    @Override
    public int getPlaintextDecodeLimit(int ciphertextLimit)
    {
        int macSize = readMac.getSize();
        int innerPlaintextLimit = getPlaintextLength(macSize, ciphertextLimit);
        return innerPlaintextLimit;
    }

    @Override
    public int getPlaintextEncodeLimit(int ciphertextLimit)
    {
        int macSize = writeMac.getSize();
        int innerPlaintextLimit = getPlaintextLength(macSize, ciphertextLimit);
        return innerPlaintextLimit;
    }

    @Override
    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
        int headerAllocation, byte[] plaintext, int offset, int len) throws IOException
    {

        int macSize = writeMac.getSize();

        int innerPlaintextLength = len;
        int totalSize = innerPlaintextLength + macSize;

        byte[] outBuf = new byte[headerAllocation + totalSize];
        int outOff = headerAllocation;

        int innerPlaintextOffset = outOff;

        System.arraycopy(plaintext, offset, outBuf, outOff, len);
        outOff += len;

        short recordType = contentType;

        byte[] mac = writeMac.calculateMac(seqNo, recordType, null, outBuf, innerPlaintextOffset, innerPlaintextLength);
        System.arraycopy(mac, 0, outBuf, outOff, mac.length);
        outOff += mac.length;

        encryptCipher.doFinal(seqNo, outBuf, headerAllocation, outOff - headerAllocation, outBuf, headerAllocation);

        if (outOff != outBuf.length)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return new TlsEncodeResult(outBuf, 0, outBuf.length, recordType);
    }

    @Override
    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
        byte[] ciphertext, int offset, int len) throws IOException
    {

        int macSize = readMac.getSize();

        if (len < macSize)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        decryptCipher.doFinal(seqNo, ciphertext, offset, len, ciphertext, offset);

        int innerPlaintextLength = len;
        innerPlaintextLength -= macSize;

        byte[] expectedMac = readMac.calculateMacConstantTime(seqNo, recordType, null, ciphertext, offset, innerPlaintextLength, len - macSize, randomData);
        boolean badMac = !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + innerPlaintextLength);

        if (badMac)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        short contentType = recordType;
        int plaintextLength = innerPlaintextLength;

        return new TlsDecodeResult(ciphertext, offset, plaintextLength, contentType);
    }

    @Override
    public void rekeyDecoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    @Override
    public void rekeyEncoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    @Override
    public boolean usesOpaqueRecordTypeDecode()
    {
        return false;
    }

    @Override
    public boolean usesOpaqueRecordTypeEncode()
    {
        return false;
    }

    private int getCiphertextLength(int macSize, int plaintextLength)
    {
        int ciphertextLength = plaintextLength;
        // Leave room for the MAC.
        ciphertextLength += macSize;
        return ciphertextLength;
    }

    private int getPlaintextLength(int macSize, int ciphertextLength)
    {
        int plaintextLength = ciphertextLength;
        // Leave room for the MAC.
        plaintextLength -= macSize;
        return plaintextLength;
    }

}
