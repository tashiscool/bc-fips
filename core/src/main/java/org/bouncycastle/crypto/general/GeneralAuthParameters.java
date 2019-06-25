package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AuthenticationParametersWithIV;

/**
 * Base class for parameter classes for algorithms allow for authentication using MACs.
 *
 * @param <T> the actual parameters type that extends this class.
 */
public abstract class GeneralAuthParameters<T extends GeneralAuthParameters>
    extends GeneralParametersWithIV<T>
    implements AuthenticationParametersWithIV<T>
{
    protected final int macLenInBits;

    /**
     * Base Constructor that takes an iv (nonce) and a tag length.
     *
     * @param algorithm algorithm mode.
     * @param blockSize block size of the cipher in bytes.
     * @param iv iv, or nonce, to be used with this algorithm.
     * @param macSizeInBits length of the checksum tag in bits.
     */
    protected GeneralAuthParameters(GeneralAlgorithm algorithm, int blockSize, byte[] iv, int macSizeInBits)
    {
        super(algorithm, blockSize, iv);

        this.macLenInBits = macSizeInBits;
    }

    /**
     * Return the size of the MAC these parameters are for.
     *
     * @return the MAC size in bits.
     */
    public int getMACSizeInBits()
    {
        return macLenInBits;
    }

    /**
     * Return an implementation of our parameterized type with an IV constructed from the passed in SecureRandom.
     *
     * @param random the SecureRandom to use as the source of IV data.
     * @param ivLen the length (in bytes) of the IV to be generated.
     * @return a new instance of our parameterized type with a new IV.
     */
    public T withIV(SecureRandom random, int ivLen)
    {
        return create(this.getAlgorithm(), this.getAlgorithm().createIvIfNecessary(ivLen, random));
    }

    /**
     * Create a parameter set with the specified MAC size associated with it.
     *
     * @param macSizeInBits bit length of the MAC length.
     * @return the new parameter set.
     */
    public T withMACSize(int macSizeInBits)
    {
        return create(this.getAlgorithm(), this.getIV(), macSizeInBits);
    }

    protected T create(GeneralAlgorithm algorithm, byte[] iv)
    {
        return create(algorithm, iv, this.getMACSizeInBits());
    }

    abstract T create(GeneralAlgorithm algorithm, byte[] iv, int macSizeInBits);
}
