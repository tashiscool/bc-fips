package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

/**
 * Base class for Elliptic Curve (EC) keys.
 */
public abstract class AsymmetricECKey
    implements AsymmetricKey
{
    private final boolean    approvedModeOnly;
    private final Algorithm algorithm;
    private final ECDomainParameters domainParameters;

    AsymmetricECKey(Algorithm algorithm, ECDomainParameters domainParameters)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
    }

    AsymmetricECKey(Algorithm algorithm, ECDomainParametersID domainParameterID)
    {
        this(algorithm, ECDomainParametersIndex.lookupDomainParameters(domainParameterID));
    }

    AsymmetricECKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier)
    {
        this(algorithm, ECDomainParameters.decodeCurveParameters(algorithmIdentifier));
    }

    /**
      * Return the algorithm this Elliptic Curve key is for.
      *
      * @return the key's algorithm.
      */
    public final Algorithm getAlgorithm()
    {
        if (this instanceof AsymmetricECPrivateKey)
        {
            checkApprovedOnlyModeStatus();
        }

        return algorithm;
    }

    /**
     * Return the Elliptic Curve domain parameters associated with this key.
     *
     * @return the EC domain parameters for the key.
     */
    public final ECDomainParameters getDomainParameters()
    {
        if (this instanceof AsymmetricECPrivateKey)
        {
            checkApprovedOnlyModeStatus();
        }

        return domainParameters;
    }

    protected final void checkApprovedOnlyModeStatus()
    {
        if (approvedModeOnly != CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("No access to key in current thread.");
        }
    }
}
