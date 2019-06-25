package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.util.EntropyUtil;

/**
 * Base class for DRBG/RNG SecureRandom implementations that use non-FIPS approved algorithms.
 */
public final class GeneralSecureRandom
    extends SecureRandom
{
    private final SecureRandom randomSource;
    private final DRBG drbg;
    private final EntropySource entropySource;
    private final boolean predictionResistant;

    GeneralSecureRandom(SecureRandom randomSource, DRBG drbg, EntropySource entropySource, boolean predictionResistant)
    {
        this.randomSource = randomSource;
        this.drbg = drbg;
        this.entropySource = entropySource;
        this.predictionResistant = predictionResistant;
    }

    public void setSeed(byte[] seed)
    {
        synchronized (this)
        {
            if (randomSource != null)
            {
                this.randomSource.setSeed(seed);
            }
        }
    }

    public void setSeed(long seed)
    {
        synchronized (this)
        {
            // this will happen when SecureRandom() is created
            if (randomSource != null)
            {
                this.randomSource.setSeed(seed);
            }
        }
    }

    public void nextBytes(byte[] bytes)
    {
        this.nextBytes(bytes, null);
    }

    public void nextBytes(byte[] bytes, byte[] additionalInput)
    {
        synchronized (this)
        {
            if (bytes == null)
            {
                throw new NullPointerException("bytes cannot be null");
            }
            if (bytes.length != 0)
            {
                // check if a reseed is required...
                if (drbg.generate(bytes, additionalInput, predictionResistant) < 0)
                {
                    drbg.reseed(null);
                    drbg.generate(bytes, additionalInput, predictionResistant);
                }
            }
        }
    }

    public byte[] generateSeed(int numBytes)
    {
        return EntropyUtil.generateSeed(entropySource, numBytes);
    }

    /**
     * Return the block size of the underlying DRBG
     *
     * @return number of bits produced each cycle.
     */
    public int getBlockSize()
    {
        return drbg.getBlockSize();
    }

    /**
     * Force a reseed.
     */
    public void reseed()
    {
        drbg.reseed(null);
    }

    /**
     * Force a reseed with additional input.
     *
     * @param additionalInput additional input to be used in conjunction with reseed.
     */
    public void reseed(byte[] additionalInput)
    {
        drbg.reseed(additionalInput);
    }
}
