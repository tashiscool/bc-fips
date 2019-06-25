package org.bouncycastle.crypto.general;

class X931PseudoRandom
    implements DRBG
{
    private final X931RNG drbg;

    X931PseudoRandom(X931RNG drbg)
    {
        this.drbg = drbg;
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

    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        if (additionalInput != null)
        {
            throw new IllegalArgumentException("X9.31 PRNG does not use additionalInput");
        }

        synchronized (this)
        {
            // check if a reseed is required...
            if (drbg.generate(output, predictionResistant) < 0)
            {
                drbg.reseed();
                return drbg.generate(output, predictionResistant);
            }

            return output.length;
        }
    }

    public void reseed(byte[] additionalInput)
    {
        if (additionalInput != null)
        {
            throw new IllegalArgumentException("X9.31 PRNG does not use additionalInput");
        }

        synchronized (this)
        {
            drbg.reseed();
        }
    }

    /**
     * Force a reseed.
     */
    public void reseed()
    {
        synchronized (this)
        {
            drbg.reseed();
        }
    }
}
