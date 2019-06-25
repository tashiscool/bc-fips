package org.bouncycastle.crypto.internal;

import org.bouncycastle.crypto.Algorithm;

public class ValidatedSymmetricKey
{
    private final Algorithm algorithm;
    private final byte[] keyBytes;

    public ValidatedSymmetricKey(Algorithm algorithm, byte[] keyBytes)
    {
        this.algorithm = algorithm;
        this.keyBytes = keyBytes;
    }

    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getKeyBytes()
    {
        return keyBytes;
    }

    public int getKeySizeInBits()
    {
        return keyBytes.length * 8;
    }
}
