/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;


public class DsaKeyParameters
    extends AsymmetricKeyParameter
{
    private DsaParameters    params;

    public DsaKeyParameters(
        boolean         isPrivate,
        DsaParameters   params)
    {
        super(isPrivate);

        this.params = params;
    }   

    public DsaParameters getParameters()
    {
        return params;
    }
}
