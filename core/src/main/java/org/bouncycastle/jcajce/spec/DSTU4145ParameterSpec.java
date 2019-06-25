package org.bouncycastle.jcajce.spec;

import java.security.spec.ECParameterSpec;

import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.util.Arrays;

/**
 * ParameterSpec for a DSTU4145 key.
 */
public class DSTU4145ParameterSpec
    extends ECParameterSpec
{
    private final byte[]             dke;
    private final ECDomainParameters parameters;

    public DSTU4145ParameterSpec(
        ECDomainParameters parameters)
    {
        this(parameters, ECUtil.convertToSpec(parameters), DSTU4145Params.getDefaultDKE());
    }

    private DSTU4145ParameterSpec(ECDomainParameters parameters, ECParameterSpec ecParameterSpec, byte[] dke)
    {
        super(ecParameterSpec.getCurve(), ecParameterSpec.getGenerator(), ecParameterSpec.getOrder(), ecParameterSpec.getCofactor());

        this.parameters = parameters;
        this.dke = Arrays.clone(dke);
    }

    public byte[] getDKE()
    {
        return Arrays.clone(dke);
    }

    public boolean equals(Object o)
    {
        if (o instanceof DSTU4145ParameterSpec)
        {
            DSTU4145ParameterSpec other = (DSTU4145ParameterSpec)o;
            
            return this.parameters.equals(other.parameters);
        }
        
        return false;
    }
    
    public int hashCode()
    {
        return this.parameters.hashCode();
    }
}
