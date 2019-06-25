/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;


class Gost3410KeyParameters
        extends AsymmetricKeyParameter
{
    private Gost3410Parameters    params;

    public Gost3410KeyParameters(
        boolean         isPrivate,
        Gost3410Parameters   params)
    {
        super(isPrivate);

        this.params = params;
    }

    public Gost3410Parameters getParameters()
    {
        return params;
    }
}
