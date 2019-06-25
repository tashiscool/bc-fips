package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.Parameters;

/**
 * Base class for parameter types used in FIPS implementations.
 */
public class FipsParameters
    implements Parameters
{
    private final FipsAlgorithm algorithm;

    // package protect construction
    FipsParameters(FipsAlgorithm algorithm)
    {
        this.algorithm = algorithm;
    }

    /**
     * Return the algorithm these parameters are associated with.
     *
     * @return the algorithm these parameters are for.
     */
    public FipsAlgorithm getAlgorithm()
    {
        return algorithm;
    }
}
