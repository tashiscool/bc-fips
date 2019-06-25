package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * Base class for parameter classes for algorithms that require an initialization vector or nonce.
 *
 * @param <T> the actual parameters type that extends this class.
 */
public abstract class GeneralParametersWithIV<T extends GeneralParameters>
    extends GeneralParameters<GeneralAlgorithm>
    implements ParametersWithIV<T>
{
    protected final int blockSize;
    protected final byte[] iv;

    GeneralParametersWithIV(GeneralAlgorithm algorithm, int blockSize, byte[] iv)
    {
        super(algorithm);

        this.blockSize = blockSize;
        this.iv = iv;
    }

    /**
     * Return a copy of the current IV value.
     *
     * @return the current IV.
     */
    public byte[] getIV()
    {
        return Arrays.clone(iv);
    }

    /**
     * Return an implementation of our parameterized type with an IV constructed from the passed in SecureRandom.
     *
     * @param random the SecureRandom to use as the source of IV data.
     * @return a new instance of our parameterized type with a new IV.
     */
    public T withIV(SecureRandom random)
    {
        return create(this.getAlgorithm(), this.getAlgorithm().createDefaultIvIfNecessary(blockSize, random));
    }

    /**
     * Return an implementation of our parameterized type containing the passed in IV.
     *
     * @param iv the bytes making up the iv, or nonce, to use.
     * @return a new instance of our parameterized type with a new IV.
     */
    public T withIV(byte[] iv)
    {
        return create(this.getAlgorithm(), Arrays.clone(iv));
    }

    abstract T create(GeneralAlgorithm algorithm, byte[] iv);
}
