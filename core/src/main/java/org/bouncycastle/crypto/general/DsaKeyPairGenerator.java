/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DsaKeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DsaParameters;
import org.bouncycastle.crypto.internal.params.DsaPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.DsaPublicKeyParameters;

/**
 * a DSA key pair generator.
 *
 * This generates DSA keys in line with the method described
 * in <i>FIPS 186-3 B.1 FFC Key Pair Generation</i>.
 */
class DsaKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(1);

    private DsaKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DsaKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DsaParameters dsaParams = param.getParameters();

        BigInteger x = generatePrivateKey(dsaParams.getQ(), param.getRandom());
        BigInteger y = calculatePublicKey(dsaParams.getP(), dsaParams.getG(), x);

        return new AsymmetricCipherKeyPair(
            new DsaPublicKeyParameters(y, dsaParams),
            new DsaPrivateKeyParameters(x, dsaParams));
    }

    private static BigInteger generatePrivateKey(BigInteger q, SecureRandom random)
    {
        BigInteger qSubOne = q.subtract(ONE);

        if (q.bitLength() <= 160)
        {
            /*
             * FIPS 186-4 B.1.2 Key Pair Generation by Testing Candidates
             */
            BigInteger c;
            do
            {
                c = new BigInteger(q.bitLength(), random);
            }
            while (c.compareTo(ONE) < 0 || c.compareTo(qSubOne) > 0);
            return c;
        }

        /*
         * FIPS 186-4 B.1.1 Key Pair Generation Using Extra Random Bits
         */
        BigInteger c = new BigInteger(q.bitLength() + 64, random);
        return c.mod(qSubOne).add(ONE);
    }

    private static BigInteger calculatePublicKey(BigInteger p, BigInteger g, BigInteger x)
    {
        return g.modPow(x, p);
    }
}
