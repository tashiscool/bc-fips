package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

/**
 * Base class for keys for GOST R 34.10-1994 and GOST R 34.10-2001.
 *
 * @param <T> domain parameters for the particular key type.
 */
public abstract class AsymmetricGOST3410Key<T>
    implements AsymmetricKey
{
    private final Algorithm algorithm;
    private final GOST3410Parameters<T> domainParameters;

    AsymmetricGOST3410Key(Algorithm algorithm, GOST3410Parameters<T> domainParameters)
    {
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
    }

    AsymmetricGOST3410Key(Algorithm algorithm, ASN1ObjectIdentifier acceptable, AlgorithmIdentifier algorithmIdentifier)
    {
        if (!acceptable.equals(algorithmIdentifier.getAlgorithm()))
        {
            throw new IllegalArgumentException("Unknown algorithm type: " + algorithmIdentifier.getAlgorithm());
        }

        this.algorithm = algorithm;
        this.domainParameters = (GOST3410Parameters<T>)decodeDomainParameters(algorithmIdentifier);
    }

    private static GOST3410Parameters decodeDomainParameters(AlgorithmIdentifier algorithmIdentifier)
    {
        if (KeyUtils.isNotNull(algorithmIdentifier.getParameters()))
        {
            GOST3410PublicKeyAlgParameters params = GOST3410PublicKeyAlgParameters.getInstance(algorithmIdentifier.getParameters());

            return new GOST3410Parameters<GOST3410DomainParameters>(params.getPublicKeyParamSet(), params.getDigestParamSet(), params.getDigestParamSet());
        }

        return null;
    }

    /**
      * Return the algorithm this DSA key is for.
      *
      * @return the key's algorithm.
      */
    public final Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the domain parameters associated with this key.These will either
     * be for GOST R 34.10-1994 or GOST R 34.10-2001 depending on the key type.
     *
     * @return the GOST3410 domain parameters.
     */
    public final GOST3410Parameters<T> getParameters()
    {
        return domainParameters;
    }

    protected final void checkApprovedOnlyModeStatus()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("No access to key in current thread.");
        }
    }
}
