package org.bouncycastle.tls.crypto;

public class TlsCounterData
{
    protected final long seqNo;

    public TlsCounterData(long seqNo)
    {
        this.seqNo = seqNo;
    }

    public long getSeqNo()
    {
        return seqNo;
    }

}
