/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DsaParameters;

public class DsaKeyGenerationParameters
    extends KeyGenerationParameters
{
    private DsaParameters params;

    public DsaKeyGenerationParameters(
        SecureRandom    random,
        DsaParameters   params)
    {
        super(random, params.getP().bitLength() - 1);

        this.params = params;
    }

    public DsaParameters getParameters()
    {
        return params;
    }
}
