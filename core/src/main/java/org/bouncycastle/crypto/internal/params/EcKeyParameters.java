/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

public class EcKeyParameters
    extends AsymmetricKeyParameter
{
    EcDomainParameters params;

    protected EcKeyParameters(
        boolean             isPrivate,
        EcDomainParameters  params)
    {
        super(isPrivate);

        this.params = params;
    }

    public EcDomainParameters getParameters()
    {
        return params;
    }
}
