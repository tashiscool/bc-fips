/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.general.Gost3410KeyGenerationParameters;
import org.bouncycastle.crypto.general.Gost3410Parameters;
import org.bouncycastle.crypto.general.Gost3410PrivateKeyParameters;
import org.bouncycastle.crypto.general.Gost3410PublicKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * a GOST3410 key pair generator.
 * This generates GOST3410 keys in line with the method described
 * in GOST R 34.10-94.
 */
class Gost3410KeyPairGenerator
        implements AsymmetricCipherKeyPairGenerator
    {
        private static final BigInteger ZERO = BigInteger.valueOf(0);

        private Gost3410KeyGenerationParameters param;

        public void init(
            KeyGenerationParameters param)
        {
            this.param = (Gost3410KeyGenerationParameters)param;
        }

        public AsymmetricCipherKeyPair generateKeyPair()
        {
            BigInteger      p, q, a, x, y;
            Gost3410Parameters   GOST3410Params = param.getParameters();
            SecureRandom    random = param.getRandom();

            q = GOST3410Params.getQ();
            p = GOST3410Params.getP();
            a = GOST3410Params.getA();

            do
            {
                x = new BigInteger(256, random);
            }
            while (x.equals(ZERO) || x.compareTo(q) >= 0);

            //
            // calculate the public key.
            //
            y = a.modPow(x, p);

            return new AsymmetricCipherKeyPair(
                    new Gost3410PublicKeyParameters(y, GOST3410Params),
                    new Gost3410PrivateKeyParameters(x, GOST3410Params));
        }
    }
