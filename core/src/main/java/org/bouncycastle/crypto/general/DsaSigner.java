package org.bouncycastle.crypto.general;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DSA;
import org.bouncycastle.crypto.internal.params.DsaKeyParameters;
import org.bouncycastle.crypto.internal.params.DsaParameters;
import org.bouncycastle.crypto.internal.params.DsaPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.DsaPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;

/**
 * The Digital Signature Algorithm - as described in "Handbook of Applied
 * Cryptography", pages 452 - 453.
 */
class DsaSigner
    implements DSA
{
    private final DsaKCalculator kCalculator;

    private DsaKeyParameters key;
    private SecureRandom    random;

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public DsaSigner(DsaKCalculator kCalculator)
    {
        this.kCalculator = kCalculator;
    }

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom    rParam = (ParametersWithRandom)param;

                this.random = rParam.getRandom();
                this.key = (DsaPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                throw new IllegalArgumentException("No random provided where one required.");
            }
        }
        else
        {
            this.key = (DsaPublicKeyParameters)param;
        }
    }

    /**
     * generate a signature for the given message using the key we were
     * initialised with. For conventional DSA the message should be a SHA-1
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public BigInteger[] generateSignature(
        byte[] message)
    {
        DsaParameters params = key.getParameters();
        BigInteger      m = calculateE(params.getQ(), message);

        if (kCalculator.isDeterministic())
        {
            kCalculator.init(params.getQ(), ((DsaPrivateKeyParameters)key).getX(), message);
        }
        else
        {
            kCalculator.init(params.getQ(), random);
        }

        BigInteger  k = kCalculator.nextK();

        // the randomizer is to conceal timing information related to k and x.
        BigInteger  r = params.getG().modPow(k.add(getRandomizer(params.getQ(), random)), params.getP()).mod(params.getQ());

        k = k.modInverse(params.getQ()).multiply(
                    m.add(((DsaPrivateKeyParameters)key).getX().multiply(r)));

        BigInteger  s = k.mod(params.getQ());

        BigInteger[]  res = new BigInteger[2];

        res[0] = r;
        res[1] = s;

        return res;
    }

    /**
     * return true if the value r and s represent a DSA signature for
     * the passed in message for standard DSA the message should be a
     * SHA-1 hash of the real message to be verified.
     */
    public boolean verifySignature(
        byte[]      message,
        BigInteger  r,
        BigInteger  s)
    {
        DsaParameters   params = key.getParameters();
        BigInteger      m = calculateE(params.getQ(), message);
        BigInteger      zero = BigInteger.valueOf(0);

        if (zero.compareTo(r) >= 0 || params.getQ().compareTo(r) <= 0)
        {
            return false;
        }

        if (zero.compareTo(s) >= 0 || params.getQ().compareTo(s) <= 0)
        {
            return false;
        }

        BigInteger  w = s.modInverse(params.getQ());

        BigInteger  u1 = m.multiply(w).mod(params.getQ());
        BigInteger  u2 = r.multiply(w).mod(params.getQ());

        u1 = params.getG().modPow(u1, params.getP());
        u2 = ((DsaPublicKeyParameters)key).getY().modPow(u2, params.getP());

        BigInteger  v = u1.multiply(u2).mod(params.getP()).mod(params.getQ());

        return v.equals(r);
    }

    private BigInteger calculateE(BigInteger n, byte[] message)
    {
        if (n.bitLength() >= message.length * 8)
        {
            return new BigInteger(1, message);
        }
        else
        {
            byte[] trunc = new byte[n.bitLength() / 8];

            System.arraycopy(message, 0, trunc, 0, trunc.length);

            return new BigInteger(1, trunc);
        }
    }

    private BigInteger getRandomizer(BigInteger q, SecureRandom provided)
    {
        // Calculate a random multiple of q to add to k. Note that g^q = 1 (mod p), so adding multiple of q to k does not change r.
        int randomBits = 7;

        return new BigInteger(randomBits, provided).add(BigInteger.valueOf(128)).multiply(q);
    }
}
