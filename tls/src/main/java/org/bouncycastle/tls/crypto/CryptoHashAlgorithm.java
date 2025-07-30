package org.bouncycastle.tls.crypto;

public abstract class CryptoHashAlgorithm
{
    public static final int md5 = 1;
    public static final int sha1 = 2;
    public static final int sha224 = 3;
    public static final int sha256 = 4;
    public static final int sha384 = 5;
    public static final int sha512 = 6;
    public static final int sm3 = 7;
    public static final int gostr3411_2012_256 = 8; // intrinsic
    // public static final short gostr3411_94_priv = 0xed;
    // public static final short gostr3411_2012_256_priv = 0xee;
    // public static final short gostr3411_2012_512_priv = 0xef;
}
