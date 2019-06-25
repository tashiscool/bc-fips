package org.bouncycastle.crypto.fips;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;

/**
 * Base class for FIPS approved algorithm identifier implementations.
 */
public class FipsAlgorithm
    implements Algorithm
{
    private final Enum basicVariation;
    private final Enum additionalVariation;
    private final String name;

    // package protect construction
    FipsAlgorithm(String name)
    {
        this(name, null, null);
    }

    FipsAlgorithm(String name, Enum basicVariation)
    {
        this(name, basicVariation, null);
    }

    FipsAlgorithm(FipsAlgorithm baseAlgorithm, Enum basicVariation)
    {
        this(baseAlgorithm.getName(), basicVariation, null);
    }

    FipsAlgorithm(FipsAlgorithm baseAlgorithm, Enum basicVariation, Padding additionalVariation)
    {
        this(baseAlgorithm.getName(), basicVariation, additionalVariation);
    }

    FipsAlgorithm(String name, Enum basicVariation, Padding additionalVariation)
    {
        this.basicVariation = basicVariation;
        this.additionalVariation = additionalVariation;
        if (basicVariation instanceof Mode)
        {
            this.name = name + "/" + ((Mode)basicVariation).getBaseMode().getCode() + ((additionalVariation != null) ? "/" + additionalVariation.getBasePadding().getCode() : "");
        }
        else if (basicVariation instanceof FipsKDF.PRF)
        {
            this.name = name + "(" + ((FipsKDF.PRF)basicVariation).getAlgorithm().getName() + ")";
        }
        else if (basicVariation instanceof FipsKDF.AgreementKDFPRF)
        {
            this.name = name + "(" + ((FipsKDF.AgreementKDFPRF)basicVariation).getAlgorithm().getName() + ")";
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
        if (!(o instanceof FipsAlgorithm))
        {
            return false;
        }

        FipsAlgorithm other = (FipsAlgorithm)o;

        if (additionalVariation != null ? !additionalVariation.equals(other.additionalVariation) : other.additionalVariation != null)
        {
            return false;
        }
        if (basicVariation != null ? !basicVariation.equals(other.basicVariation) : other.basicVariation != null)
        {
            return false;
        }
        if (!name.equals(other.name))
        {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = name.hashCode();
        result = 31 * result + (additionalVariation != null ? additionalVariation.hashCode() : 0);
        result = 31 * result + (basicVariation != null ? basicVariation.hashCode() : 0);
        return result;
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
