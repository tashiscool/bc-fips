/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;

class EcKeyGenerationParameters
    extends KeyGenerationParameters
{
    private EcDomainParameters domainParams;

    public EcKeyGenerationParameters(
        EcDomainParameters      domainParams,
        SecureRandom            random)
    {
        super(random, domainParams.getN().bitLength());

        this.domainParams = domainParams;
    }

    public EcDomainParameters getDomainParameters()
    {
        return domainParams;
    }
}
