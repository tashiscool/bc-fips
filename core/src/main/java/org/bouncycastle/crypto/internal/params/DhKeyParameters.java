package org.bouncycastle.crypto.internal.params;


public class DhKeyParameters
    extends AsymmetricKeyParameter
{
    private DhParameters params;

    protected DhKeyParameters(
        boolean isPrivate,
        DhParameters params)
    {
        super(isPrivate);

        this.params = params;
    }   

    public DhParameters getParameters()
    {
        return params;
    }
}
