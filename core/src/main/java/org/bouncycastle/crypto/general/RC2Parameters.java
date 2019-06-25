package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.params.KeyParameterImpl;

class RC2Parameters
    extends KeyParameterImpl
{
    private int     bits;

    public RC2Parameters(
        byte[] key,
        int bits)
    {
        super(key);
        this.bits = bits;
    }

    public int getEffectiveKeyBits()
    {
        return bits;
    }
}
