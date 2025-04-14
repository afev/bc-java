package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.DTLSCounterData;
import org.bouncycastle.tls.crypto.TlsCounterData;

public class TlsGostCounter
{
    public static long getSeqNo(TlsCounterData counterData)
    {
        long seqNo;
        if (counterData instanceof DTLSCounterData)
        {
            seqNo = (((DTLSCounterData) counterData).getEpoch() & 0xFFFFFFFFL) | ((DTLSCounterData) counterData).getCleanSeqNo();
        }
        else
        {
            seqNo = counterData.getSeqNo();
        }
        return seqNo;
    }
}
