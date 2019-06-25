package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410DomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410Parameters;

/**
 * ParameterSpec for a GOST 3410 key.
 */
public final class GOST3410ParameterSpec<T extends AlgorithmParameterSpec>
    implements AlgorithmParameterSpec
{
    private GOST3410Parameters parameters;

    public GOST3410ParameterSpec(
        GOST3410Parameters parameters)
    {
        this.parameters = parameters;
    }

    public ASN1ObjectIdentifier getPublicKeyParamSet()
    {
        return parameters.getPublicKeyParamSet();
    }

    public ASN1ObjectIdentifier getDigestParamSet()
    {
        return parameters.getDigestParamSet();
    }

    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return parameters.getEncryptionParamSet();
    }

    public T getDomainParametersSpec()
    {
        if (parameters.getDomainParameters() instanceof GOST3410DomainParameters)
        {
            return (T)new GOST3410DomainParameterSpec((GOST3410DomainParameters)parameters.getDomainParameters());
        }
        else
        {
            return (T)new ECDomainParameterSpec((ECDomainParameters)parameters.getDomainParameters());
        }
    }

    public boolean equals(Object o)
    {
        if (o instanceof GOST3410ParameterSpec)
        {
            GOST3410ParameterSpec other = (GOST3410ParameterSpec)o;

            return this.parameters.equals(other.parameters);
        }

        return false;
    }

    public int hashCode()
    {
        return this.parameters.hashCode();
    }
}
