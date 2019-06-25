package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;

/**
 * Base class for the marker/algorithm ids for non-FIPS algorithms.
 */
public class GeneralAlgorithm
    implements Algorithm
{
    private final Enum basicVariation;
    private final Enum additionalVariation;
    private final String name;

    // package protect construction
    GeneralAlgorithm(String name)
    {
        this(name, null, null);
    }

    GeneralAlgorithm(String name, Enum basicVariation)
    {
        this(name, basicVariation, null);
    }

    GeneralAlgorithm(GeneralAlgorithm baseAlgorithm, Enum basicVariation)
    {
        this(baseAlgorithm.getName(), basicVariation, null);
    }

    GeneralAlgorithm(GeneralAlgorithm baseAlgorithm, Enum basicVariation, Padding additionalVariation)
    {
        this(baseAlgorithm.getName(), basicVariation, additionalVariation);
    }

    GeneralAlgorithm(String name, Enum basicVariation, Padding additionalVariation)
    {
        this.basicVariation = basicVariation;
        this.additionalVariation = additionalVariation;
        if (basicVariation instanceof Mode)
        {
            this.name = name + "/" + ((Mode)basicVariation).getBaseMode().getCode() + ((additionalVariation != null) ? "/" + additionalVariation.getBasePadding().getCode() : "");
        }
        else
        {
            this.name = name;
        }
    }

    Enum basicVariation()
    {
        return basicVariation;
    }

    Enum additionalVariation()
    {
        return additionalVariation;
    }

    public String getName()
    {
        return name;
    }

    public final boolean requiresAlgorithmParameters()
    {
        return basicVariation instanceof Mode && ((Mode)basicVariation).getBaseMode().expectsIV();
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(o instanceof GeneralAlgorithm))
        {
            return false;
        }

        GeneralAlgorithm other = (GeneralAlgorithm)o;

        if (!isEqual(additionalVariation, other.additionalVariation))
        {
            return false;
        }
        if (!isEqual(basicVariation, other.basicVariation))
        {
            return false;
        }
        if (!name.equals(other.name))
        {
            return false;
        }

        return true;
    }

    private boolean isEqual(Object a, Object b)
    {
        return a == b || ((a != null) && a.equals(b));
    }

    @Override
    public int hashCode()
    {
        int result =  name.hashCode();

        result = 31 * result + (basicVariation != null ? basicVariation.hashCode() : 0);
        result = 31 * result + (additionalVariation != null ? additionalVariation.hashCode() : 0);

        return result;
    }

    byte[] checkIv(byte[] iv, int blockSize)
    {
        return ((Mode)this.basicVariation()).checkIv(iv, blockSize);
    }

    byte[] createDefaultIvIfNecessary(int blockSize, SecureRandom random)
    {
        return ((Mode)this.basicVariation()).createDefaultIvIfNecessary(blockSize, random);
    }

    byte[] createIvIfNecessary(int ivLen, SecureRandom random)
    {
        return ((Mode)this.basicVariation()).createIvIfNecessary(ivLen, random);
    }
}
