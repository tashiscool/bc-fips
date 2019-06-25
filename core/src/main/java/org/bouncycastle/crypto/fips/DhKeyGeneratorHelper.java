/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.params.DhParameters;
import org.bouncycastle.util.BigIntegers;

class DhKeyGeneratorHelper
{
    static final DhKeyGeneratorHelper INSTANCE = new DhKeyGeneratorHelper();

    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private DhKeyGeneratorHelper()
    {
    }

    BigInteger calculatePrivate(DhParameters dhParams, SecureRandom random)
    {
        int limit = dhParams.getL();

        if (limit != 0)
        {
            return new BigInteger(limit, random).setBit(limit - 1);
        }

        BigInteger min = TWO;
        int m = dhParams.getM();
        if (m != 0)
        {
            min = ONE.shiftLeft(m - 1);
        }

        BigInteger q = dhParams.getQ();
        if (q == null)
        {
            q = dhParams.getP();
        }
        BigInteger max = q.subtract(TWO);

        return BigIntegers.createRandomInRange(min, max, random);
    }

    BigInteger calculatePublic(DhParameters dhParams, BigInteger x)
    {
        return dhParams.getG().modPow(x, dhParams.getP());
    }
}
