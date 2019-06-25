package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ua.DSTU4145BinaryField;
import org.bouncycastle.asn1.ua.DSTU4145ECBinary;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;

/**
 * Base class for DSTU-4145 keys.
 */
public abstract class AsymmetricDSTU4145Key
    implements AsymmetricKey
{
    private final Algorithm algorithm;
    private final DSTU4145Parameters parameters;

    protected final AlgorithmIdentifier dstu4145Identifier;

    AsymmetricDSTU4145Key(Algorithm algorithm, DSTU4145Parameters parameters)
    {
        this.algorithm = algorithm;
        this.parameters = parameters;
        this.dstu4145Identifier = null;
    }

    AsymmetricDSTU4145Key(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier)
    {
        this.algorithm = algorithm;
        this.parameters = decodeDomainParameters(algorithmIdentifier);
        this.dstu4145Identifier = algorithmIdentifier;
    }

    private static DSTU4145Parameters decodeDomainParameters(AlgorithmIdentifier algorithmIdentifier)
    {
        ASN1ObjectIdentifier algOid = algorithmIdentifier.getAlgorithm();

        if (!(algOid.equals(UAObjectIdentifiers.dstu4145be) || algOid.equals(UAObjectIdentifiers.dstu4145le)))
        {
            throw new IllegalArgumentException("Unknown algorithm type: " + algorithmIdentifier.getAlgorithm());
        }

        DSTU4145Params dstuParams = DSTU4145Params.getInstance(algorithmIdentifier.getParameters());

        if (dstuParams.isNamedCurve())
        {
            ASN1ObjectIdentifier curveOid = dstuParams.getNamedCurve();

            return new DSTU4145Parameters(curveOid, dstuParams.getDKE());
        }
        else
        {
            DSTU4145ECBinary binary = dstuParams.getECBinary();
            byte[] b_bytes = binary.getB();
            if (algorithmIdentifier.getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
            {
                reverseBytes(b_bytes);
            }
            DSTU4145BinaryField field = binary.getField();
            BigInteger coFactor = deriveDSTUCofactor(field.getM(), binary.getN());
            ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), new BigInteger(1, b_bytes), binary.getN(), coFactor);
            byte[] g_bytes = binary.getG();
            if (algorithmIdentifier.getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
            {
                reverseBytes(g_bytes);
            }

            return new DSTU4145Parameters(new ECDomainParameters(curve, DSTU4145PointEncoder.decodePoint(curve, g_bytes), binary.getN(), coFactor));
        }
    }

    /**
     * Return the algorithm this DSTU4145 key is for.
     *
     * @return the key's algorithm.
     */
    public final Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the domain parameters for this DSTU4145 key.
     *
     * @return the DSTU4145 domain parameters.
     */
    public final DSTU4145Parameters getParameters()
    {
        return parameters;
    }

    protected final void checkApprovedOnlyModeStatus()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("No access to key in current thread.");
        }
    }

    protected static void reverseBytes(byte[] bytes)
    {
        byte tmp;

        for (int i = 0; i < bytes.length / 2; i++)
        {
            tmp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = tmp;
        }
    }

    private static BigInteger deriveDSTUCofactor(int m, BigInteger order)
    {
        int pow = order.bitLength();
        if (pow > 1 && !order.testBit(pow - 2))
        {
            --pow;
        }
        return ECConstants.ONE.shiftLeft(Math.max(0, m - pow));
    }
}
