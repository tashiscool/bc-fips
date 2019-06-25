package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;

class ElGamalKeyParameters
    extends AsymmetricKeyParameter
{
    private final ElGamalParameters    params;

    protected ElGamalKeyParameters(
        boolean              isPrivate,
        ElGamalParameters    params)
    {
        super(isPrivate);

        this.params = params;
    }   

    public ElGamalParameters getParameters()
    {
        return params;
    }
}
