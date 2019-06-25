package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.internal.BasicAgreement;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcMqvPrivateParameters;
import org.bouncycastle.crypto.internal.params.EcMqvPublicParameters;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

class EcMqvBasicAgreement
    implements BasicAgreement
{
    EcMqvPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (EcMqvPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public BigInteger calculateAgreement(CipherParameters pubKey)
    {
        EcMqvPublicParameters pubParams = (EcMqvPublicParameters)pubKey;

        EcPrivateKeyParameters staticPrivateKey = privParams.getStaticPrivateKey();

        if (!privParams.getStaticPrivateKey().getParameters().equals(pubParams.getStaticPublicKey().getParameters()))
        {
            throw new IllegalKeyException("ECMQV public key components have wrong domain parameters");
        }

        ECPoint agreement = calculateMqvAgreement(staticPrivateKey.getParameters(), staticPrivateKey,
            privParams.getEphemeralPrivateKey(), privParams.getEphemeralPublicKey(),
            pubParams.getStaticPublicKey(), pubParams.getEphemeralPublicKey()).normalize();

        if (agreement.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid agreement value for MQV");
        }

        return agreement.getAffineXCoord().toBigInteger();
    }

    // The ECMQV Primitive as described in SEC-1, 3.4
    private ECPoint calculateMqvAgreement(
        EcDomainParameters parameters,
        EcPrivateKeyParameters d1U,
        EcPrivateKeyParameters  d2U,
        EcPublicKeyParameters Q2U,
        EcPublicKeyParameters   Q1V,
        EcPublicKeyParameters   Q2V)
    {
        BigInteger n = parameters.getN();
        int e = (n.bitLength() + 1) / 2;
        BigInteger powE = ECConstants.ONE.shiftLeft(e);

        ECCurve curve = parameters.getCurve();

        ECPoint[] points = new ECPoint[]{
            // The Q2U public key is optional
            ECAlgorithms.importPoint(curve, Q2U.getQ()),
            ECAlgorithms.importPoint(curve, Q1V.getQ()),
            ECAlgorithms.importPoint(curve, Q2V.getQ())
        };

        curve.normalizeAll(points);

        ECPoint q2u = points[0], q1v = points[1], q2v = points[2];

        BigInteger x = q2u.getAffineXCoord().toBigInteger();
        BigInteger xBar = x.mod(powE);
        BigInteger Q2UBar = xBar.setBit(e);
        BigInteger s = d1U.getD().multiply(Q2UBar).add(d2U.getD()).mod(n);

        BigInteger xPrime = q2v.getAffineXCoord().toBigInteger();
        BigInteger xPrimeBar = xPrime.mod(powE);
        BigInteger Q2VBar = xPrimeBar.setBit(e);

        BigInteger hs = parameters.getH().multiply(s).mod(n);

        return ECAlgorithms.sumOfTwoMultiplies(
            q1v, Q2VBar.multiply(hs).mod(n), q2v, hs);
    }
}
