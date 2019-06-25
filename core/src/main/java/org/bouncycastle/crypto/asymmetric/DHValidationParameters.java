package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.util.Arrays;

/**
 * Validation parameters for confirming Diffie-Hellman parameter generation.
 */
public class DHValidationParameters
{
    private int usageIndex;
    private byte[]  seed;
    private int     counter;

    /**
     * Base constructor - a seed, the counter will be set to -1.
     *
     * @param seed the seed used to generate the parameters.
     */
    public DHValidationParameters(
        byte[] seed)
    {
        this(seed, -1, -1);
    }

    /**
     * Constructor with a seed and a (p, q) counter for it.
     *
     * @param seed the seed used to generate the parameters.
     * @param counter the counter value associated with using the seed to generate the parameters.
     */
    public DHValidationParameters(
        byte[] seed,
        int counter)
    {
        this(seed, counter, -1);
    }

    /**
     * Base constructor with a seed, counter, and usage index.
     *
     * @param seed the seed value.
     * @param counter  (p, q) counter - -1 if not avaliable.
     * @param usageIndex the usage index.
     */
    public DHValidationParameters(
        byte[] seed,
        int counter,
        int usageIndex)
    {
        this.seed = Arrays.clone(seed);
        this.counter = counter;
        this.usageIndex = usageIndex;
    }

    /**
     * Return the (p, q) counter value.
     *
     * @return  the (p, q) counter value, -1 if unavailable.
     */
    public int getCounter()
    {
        return counter;
    }

    /**
     * Return the seed used for the parameter generation.
     *
     * @return the seed array.
     */
    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    /**
     * Return the usage index, -1 if none given.
     *
     * @return the usage index.
     */
    public int getUsageIndex()
    {
        return usageIndex;
    }

    public int hashCode()
    {
        int code = this.counter;

        code += 37 * Arrays.hashCode(seed);
        code += 37 * usageIndex;

        return code;
    }
    
    public boolean equals(
        Object o)
    {
        if (!(o instanceof DHValidationParameters))
        {
            return false;
        }

        DHValidationParameters other = (DHValidationParameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        if (other.usageIndex != this.usageIndex)
        {
            return false;
        }

        return Arrays.areEqual(this.seed, other.seed);
    }
}
