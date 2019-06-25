package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410NamedParameters;
import org.bouncycastle.asn1.cryptopro.GOST3410ParamSetParameters;

/**
 * Generic base type for GOST R 34.10-1994 and GOST R 34.10-2001.
 *
 * @param <T> the domain parameters associated with these parameters.
 */
public final class GOST3410Parameters<T>
{
    private final ASN1ObjectIdentifier publicKeyParamSet;
    private final ASN1ObjectIdentifier digestParamSet;
    private final ASN1ObjectIdentifier encryptionParamSet;
    private final T domainParameters;

    /**
     * Constructor from the public key parameter set object identifier.
     *
     * @param publicKeyParamSet the public key parameter set object identifier.
     */
    public GOST3410Parameters(ASN1ObjectIdentifier publicKeyParamSet)
    {
        this(publicKeyParamSet, CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet, null, (T)getDomainParameters(publicKeyParamSet));
    }

    /**
     * Constructor for signing parameters.
     *
     * @param publicKeyParamSet the public key parameter set object identifier.
     * @param digestParamSet the object identifier for the digest algorithm to be associated with parameters.
     */
    public GOST3410Parameters(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet)
    {
        this(publicKeyParamSet, digestParamSet, null, (T)getDomainParameters(publicKeyParamSet));
    }

    /**
     * Constructor for signing/encryption parameters.
     *
     * @param publicKeyParamSet the public key parameter set object identifier.
     * @param digestParamSet the object identifier for the digest algorithm to be associated with parameters.
     * @param encryptionParamSet the object identifier associated with encryption algorithm to use.
     */
    public GOST3410Parameters(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet, ASN1ObjectIdentifier encryptionParamSet)
    {
        this(publicKeyParamSet, digestParamSet, encryptionParamSet, (T)getDomainParameters(publicKeyParamSet));
    }

    /**
     * Constructor for signing parameters with explicit domain parameters.
     *
     * @param publicKeyParamSet the public key parameter set object identifier.
     * @param digestParamSet the object identifier for the digest algorithm to be associated with parameters.
     * @param domainParameters the domain parameters to use.
     */
    public GOST3410Parameters(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet, T domainParameters)
    {
        this(publicKeyParamSet, digestParamSet, null, domainParameters);
    }

    /**
     * Constructor for signing/encryption parameters with explicit domain parameters.
     *
     * @param publicKeyParamSet the public key parameter set object identifier.
     * @param digestParamSet the object identifier for the digest algorithm to be associated with parameters.
     * @param encryptionParamSet the object identifier associated with encryption algorithm to use.
     * @param domainParameters the domain parameters to use.
     */
    public GOST3410Parameters(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet, ASN1ObjectIdentifier encryptionParamSet, T domainParameters)
    {
        this.publicKeyParamSet = publicKeyParamSet;
        this.digestParamSet = digestParamSet;
        this.encryptionParamSet = encryptionParamSet;
        this.domainParameters = domainParameters;
    }

    /**
     * Return the object identifier for the public key parameter set.
     *
     * @return the OID for the public key parameter set.
     */
    public ASN1ObjectIdentifier getPublicKeyParamSet()
    {
        return publicKeyParamSet;
    }

    /**
     * Return the object identifier for the digest parameter set.
     *
     * @return the OID for the digest parameter set.
     */
    public ASN1ObjectIdentifier getDigestParamSet()
    {
        return digestParamSet;
    }

    /**
     * Return the object identifier for the encryption parameter set.
     *
     * @return the OID for the encryption parameter set.
     */
    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return encryptionParamSet;
    }

    /**
     * Return the domain parameters associated with the OIDs in this parameters object.
     *
     * @return the domain parameters used by this parameters object.
     */
    public T getDomainParameters()
    {
        return domainParameters;
    }

    private static Object getDomainParameters(ASN1ObjectIdentifier oid)
    {
        GOST3410ParamSetParameters params = GOST3410NamedParameters.getByOID(oid);

        if (params != null)
        {
            return new GOST3410DomainParameters(params.getKeySize(), params.getP(), params.getQ(), params.getA());
        }

        ECDomainParameters ecParams = ECGOST3410NamedCurves.getByOID(oid);

        return new NamedECDomainParameters(oid, ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(o instanceof GOST3410Parameters))
        {
            return false;
        }

        GOST3410Parameters that = (GOST3410Parameters)o;

        if (digestParamSet != null ? !digestParamSet.equals(that.digestParamSet) : that.digestParamSet != null)
        {
            return false;
        }
        if (domainParameters != null ? !domainParameters.equals(that.domainParameters) : that.domainParameters != null)
        {
            return false;
        }
        if (encryptionParamSet != null ? !encryptionParamSet.equals(that.encryptionParamSet) : that.encryptionParamSet != null)
        {
            return false;
        }
        if (publicKeyParamSet != null ? !publicKeyParamSet.equals(that.publicKeyParamSet) : that.publicKeyParamSet != null)
        {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = publicKeyParamSet != null ? publicKeyParamSet.hashCode() : 0;
        result = 31 * result + (digestParamSet != null ? digestParamSet.hashCode() : 0);
        result = 31 * result + (encryptionParamSet != null ? encryptionParamSet.hashCode() : 0);
        result = 31 * result + (domainParameters != null ? domainParameters.hashCode() : 0);
        return result;
    }
}
