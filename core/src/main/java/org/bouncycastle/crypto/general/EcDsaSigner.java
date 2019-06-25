package org.bouncycastle.crypto.general;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DSA;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

/**
 * EC-DSA as described in X9.62
 */
class EcDsaSigner
    implements ECConstants, DSA
{
    private final DsaKCalculator kCalculator;

    private EcKeyParameters key;
    private SecureRandom    random;

    /**
     * Default configuration, random K values.
     */
    public EcDsaSigner()
    {
        this.kCalculator = new RandomDsaKCalculator();
    }

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public EcDsaSigner(DsaKCalculator kCalculator)
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
                this.key = (EcPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                if (kCalculator instanceof RandomDsaKCalculator)
                {
                    throw new IllegalArgumentException("No random provided where one required.");
                }
                this.key = (EcPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (EcPublicKeyParameters)param;
        }
    }

    // 5.3 pg 28
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
        EcDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = calculateE(n, message);
        BigInteger d = ((EcPrivateKeyParameters)key).getD();

        if (kCalculator.isDeterministic())
        {
            kCalculator.init(n, d, message);
        }
        else
        {
            kCalculator.init(n, random);
        }

        BigInteger r, s;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        // 5.3.2
        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                k = kCalculator.nextK();

                ECPoint p = basePointMultiplier.multiply(ec.getG(), k).normalize();

                // 5.3.3
                r = p.getAffineXCoord().toBigInteger().mod(n);
            }
            while (r.equals(ZERO));

            s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
        }
        while (s.equals(ZERO));

        return new BigInteger[]{ r, s };
    }

    // 5.4 pg 29
    /**
     * return true if the value r and s represent a DSA signature for
     * the passed in message (for standard DSA the message should be
     * a SHA-1 hash of the real message to be verified).
     */
    public boolean verifySignature(
        byte[]      message,
        BigInteger  r,
        BigInteger  s)
    {
        EcDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = calculateE(n, message);

        // r in the range [1,n-1]
        if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0)
        {
            return false;
        }

        // s in the range [1,n-1]
        if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0)
        {
            return false;
        }

        BigInteger c = s.modInverse(n);

        BigInteger u1 = e.multiply(c).mod(n);
        BigInteger u2 = r.multiply(c).mod(n);

        ECPoint G = ec.getG();
        ECPoint Q = ((EcPublicKeyParameters)key).getQ();

        ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, u1, Q, u2).normalize();

        // components must be bogus.
        if (point.isInfinity())
        {
            return false;
        }

        BigInteger v = point.getAffineXCoord().toBigInteger().mod(n);

        return v.equals(r);
    }

    protected BigInteger calculateE(BigInteger n, byte[] message)
    {
        int log2n = n.bitLength();
        int messageBitLength = message.length * 8;

        BigInteger e = new BigInteger(1, message);
        if (log2n < messageBitLength)
        {
            e = e.shiftRight(messageBitLength - log2n);
        }
        return e;
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
