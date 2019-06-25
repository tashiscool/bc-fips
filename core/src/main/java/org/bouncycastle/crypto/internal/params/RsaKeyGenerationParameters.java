/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.KeyGenerationParameters;

public class RsaKeyGenerationParameters
    extends KeyGenerationParameters
{
    private BigInteger publicExponent;
    private int certainty;

    public RsaKeyGenerationParameters(
        BigInteger      publicExponent,
        SecureRandom    random,
        int             strength,
        int             certainty)
    {
        super(random, strength);

        if (strength < 12)
        {
            throw new IllegalArgumentException("key strength too small");
        }

        //
        // public exponent cannot be even
        //
        if (!publicExponent.testBit(0)) 
        {
                throw new IllegalArgumentException("public exponent cannot be even");
        }
        
        this.publicExponent = publicExponent;
        this.certainty = certainty;
    }

    public BigInteger getPublicExponent()
    {
        return publicExponent;
    }

    public int getCertainty()
    {
        return certainty;
    }
}
