package org.bouncycastle.jcajce.provider;

import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

// we need this for legacy reasons
class PBKDFPBEKey
    extends SecretKeySpec
    implements PBEKey
{
    private final char[] password;
    private final byte[] salt;
    private final int iterationCount;

    public PBKDFPBEKey(byte[] bytes, String keyAlg, PBEKeySpec pbeSpec)
    {
        super(bytes, keyAlg);
        this.password = pbeSpec.getPassword();
        this.salt = pbeSpec.getSalt();
        this.iterationCount = pbeSpec.getIterationCount();
    }

    public char[] getPassword()
    {
        return password;
    }

    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public int getIterationCount()
    {
        return iterationCount;
    }
}
