/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.WNafUtil;

class EcKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    EcDomainParameters params;
    SecureRandom        random;

    public void init(
        KeyGenerationParameters param)
    {
        EcKeyGenerationParameters  ecP = (EcKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();

        if (this.random == null)
        {
            throw new IllegalArgumentException("No random provided where one required.");
        }
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with FIPS PUB 186-4, Section B.4.2
     * "Key Pair Generation by Testing Candidates".
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger upper = params.getN().subtract(BigInteger.valueOf(2));
        int nBitLength = upper.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (;;)
        {
            d = new BigInteger(nBitLength, random);

            if (d.compareTo(upper) > 0)
            {
                continue;
            }

            /*
             * Require a minimum weight of the NAF representation to prevent potentially weak private keys.
             *
             * See "Elliptic Curve Cryptography in Practice" Joppe W. Bos1, J. Alex Halderman, Nadia Heninger, Jonathan Moore, Michael Naehrig1
, and Eric Wustrow.
             */
            if (WNafUtil.getNafWeight(d) < minWeight)
            {
                continue;
            }

            break;
        }

        d = d.add(BigInteger.ONE);

        ECPoint Q = createBasePointMultiplier().multiply(params.getG(), d);

        return new AsymmetricCipherKeyPair(
            new EcPublicKeyParameters(Q, params),
            new EcPrivateKeyParameters(d, params));
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
