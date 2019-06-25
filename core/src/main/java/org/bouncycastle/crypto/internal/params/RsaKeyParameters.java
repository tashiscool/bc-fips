/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;


import java.math.BigInteger;

public class RsaKeyParameters
    extends AsymmetricKeyParameter
{
    private BigInteger      modulus;
    private BigInteger      exponent;

    public RsaKeyParameters(
        boolean     isPrivate,
        BigInteger  modulus,
        BigInteger  exponent)
    {
        super(isPrivate);

        this.modulus = modulus;
        this.exponent = exponent;
    }   

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getExponent()
    {
        return exponent;
    }
}
