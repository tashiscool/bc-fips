package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

/**
 * Base class for Diffie-Hellman keys.
 */
public abstract class AsymmetricDHKey
    implements AsymmetricKey
{
    private final boolean    approvedModeOnly;
    private final Algorithm algorithm;
    private final DHDomainParameters domainParameters;

    AsymmetricDHKey(Algorithm algorithm, DHDomainParameters domainParameters)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
    }

    AsymmetricDHKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.domainParameters = decodeDomainParameters(algorithmIdentifier);
    }

    private static DHDomainParameters decodeDomainParameters(AlgorithmIdentifier algorithmIdentifier)
    {
        ASN1ObjectIdentifier id = algorithmIdentifier.getAlgorithm();
        ASN1Encodable parameters = algorithmIdentifier.getParameters();

        if (parameters == null)
        {
            throw new NullPointerException("AlgorithmIdentifier parameters cannot be empty");
        }

        if (id.equals(OIWObjectIdentifiers.elGamalAlgorithm))
        {
            ElGamalParameter elg = ElGamalParameter.getInstance(parameters);

            return new DHDomainParameters(elg.getP(), elg.getG());
        }

        // we need the PKCS check to handle older keys marked with the X9 oid.
        if (id.equals(PKCSObjectIdentifiers.dhKeyAgreement) || KeyUtils.isDHPKCSParam(parameters))
        {
            DHParameter params = DHParameter.getInstance(parameters);

            if (params.getL() != null)
            {
                return new DHDomainParameters(params.getP(), null, params.getG(), params.getL().intValue());
            }
            else
            {
                return new DHDomainParameters(params.getP(), params.getG());
            }
        }
        else if (id.equals(X9ObjectIdentifiers.dhpublicnumber))
        {
            DomainParameters params = DomainParameters.getInstance(parameters);

            if (params.getValidationParams() != null)
            {
                return new DHDomainParameters(params.getP(), params.getQ(), params.getG(), params.getJ(),
                    new DHValidationParameters(params.getValidationParams().getSeed(), params.getValidationParams().getPgenCounter().intValue()));
            }
            else
            {
                return new DHDomainParameters(params.getP(), params.getQ(), params.getG(), params.getJ(), null);
            }
        }
        else
        {
            throw new IllegalArgumentException("Unknown algorithm type: " + id);
        }
    }

    /**
     * Return the algorithm this Diffie-Hellman key is for.
     *
     * @return the key's algorithm.
     */
    public final Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the Diffie-Hellman domain parameters associated with this key.
     *
     * @return the Diffie-Hellman domain parameters for this key.
     */
    public final DHDomainParameters getDomainParameters()
    {
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
