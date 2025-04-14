package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCounterData;

public class DTLSCounterData extends TlsCounterData
{
    private final int epoch;

    public DTLSCounterData(int epoch, long seqNo)
    {
        super(seqNo);
        this.epoch = epoch;
    }

    public int getEpoch()
    {
        return epoch;
    }

    public long getCleanSeqNo()
    {
        return seqNo;
    }

    public long getSeqNo()
    {
        return ((epoch & 0xFFFFFFFFL) << 48) | seqNo;
    }

}
