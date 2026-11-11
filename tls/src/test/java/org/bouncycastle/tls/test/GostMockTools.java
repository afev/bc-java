package org.bouncycastle.tls.test;

import org.bouncycastle.tls.ExporterLabel;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.crypto.TlsSecret;

public class GostMockTools
{
    public static void verifyMasterSecret(TlsContext context, boolean isServer)
    {
        TlsSecret masterSecret = context.getSecurityParameters().getMasterSecret();
        byte[] seed = new byte[64];
        for (int i = 0; i < seed.length; i++)
        {
            seed[i] = (byte)i;
        }
        TlsSecret material = masterSecret.deriveUsingPRF(0, ExporterLabel.dtls_srtp, seed, 60);
        System.out.println((isServer ? "Server" : "Client") + " material: " + org.bouncycastle.util.encoders.Hex.toHexString(material.extract()));
    }
}
