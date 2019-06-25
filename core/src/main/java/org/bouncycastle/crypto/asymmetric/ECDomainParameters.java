package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * Container class for Elliptic Curve domain parameters.
 */
public class ECDomainParameters
{
    private final ECCurve curve;
    private final byte[]  seed;
    private final ECPoint G;
    private final BigInteger n;
    private final BigInteger  h;

    /**
     * Constructor that assumes the co-factor h is 1.
     *
     * @param curve the curve for these domain parameters.
     * @param G the base point G for the domain parameters.
     * @param n the order for the domain parameters.
     */
    public ECDomainParameters(
        ECCurve curve,
        ECPoint G,
        BigInteger n)
    {
        this(curve, G, n, BigInteger.ONE, null);
    }

    /**
     * Constructor with explicit co-factor.
     *
     * @param curve the curve for these domain parameters.
     * @param G the base point G for the domain parameters.
     * @param n the order for the domain parameters.
     * @param h the co-factor.
     */
    public ECDomainParameters(
        ECCurve curve,
        ECPoint G,
        BigInteger n,
        BigInteger h)
    {
        this(curve, G, n, h, null);
    }

    /**
     * Constructor with explicit co-factor and generation seed.
     *
     * @param curve the curve for these domain parameters.
     * @param G the base point G for the domain parameters.
     * @param n the order for the domain parameters.
     * @param h the co-factor.
     * @param seed the seed value used to generate the domain parameters.
     */
    public ECDomainParameters(
        ECCurve curve,
        ECPoint G,
        BigInteger n,
        BigInteger h,
        byte[] seed)
    {
        this.curve = curve;
        this.G = G.normalize();
        this.n = n;
        this.h = h;
        this.seed = Arrays.clone(seed);
    }

    /**
     * Return the curve associated with these domain parameters.
     *
     * @return the domain parameters' curve.
     */
    public ECCurve getCurve()
    {
        return curve;
    }

    /**
     * Return the base point associated with these domain parameters.
     *
     * @return the domain parameters' base point.
     */
    public ECPoint getG()
    {
        return G;
    }

    /**
     * Return the order associated with these domain parameters.
     *
     * @return the domain parameters' order.
     */
    public BigInteger getN()
    {
        return n;
    }

    /**
     * Return the co-factor associated with these domain parameters.
     *
     * @return the domain parameters' co-factor.
     */
    public BigInteger getH()
    {
        return h;
    }

    /**
     * Return the generation seed associated with these domain parameters.
     *
     * @return the domain parameters' seed.
     */
    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(o instanceof ECDomainParameters))
        {
            return false;
        }

        ECDomainParameters that = (ECDomainParameters)o;

        if (!G.equals(that.G))
        {
            return false;
        }
        if (!curve.equals(that.curve))
        {
            return false;
        }
        if (!h.equals(that.h))
        {
            return false;
        }
        if (!n.equals(that.n))
        {
            return false;
        }
        // we need to ignore the seed as it will not always be set (JDK issue)

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = curve.hashCode();
        // we need to ignore the seed as it will not always be set (JDK issue)
        result = 31 * result + G.hashCode();
        result = 31 * result + n.hashCode();
        result = 31 * result + h.hashCode();
        return result;
    }

    static ECDomainParameters decodeCurveParameters(AlgorithmIdentifier algId)
    {
        if (!algId.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            throw new IllegalArgumentException("Unknown algorithm type: " + algId.getAlgorithm());
        }

        X962Parameters params = X962Parameters.getInstance(algId.getParameters());

        X9ECParameters x9;

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();

            x9 = CustomNamedCurves.getByOID(oid);
            if (x9 == null)
            {
                x9 = ECNamedCurveTable.getByOID(oid);
            }
            return new NamedECDomainParameters(oid, x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
        }
        else if (!params.isImplicitlyCA())
        {
            x9 = X9ECParameters.getInstance(params.getParameters());
            return new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
        }
        else
        {
            return new ECImplicitDomainParameters(CryptoServicesRegistrar.<ECDomainParameters>getProperty(CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA));
        }
    }
}
