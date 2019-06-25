package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.ua.DSTU4145ECBinary;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.math.ec.ECCurve;

/**
 * Class for DSTU-4145 private keys.
 */
public final class AsymmetricDSTU4145PrivateKey
    extends AsymmetricDSTU4145Key
    implements AsymmetricPrivateKey
{
    private final int        hashCode;

    private PrivateKeyInfo privKeyInfo;
    private BigInteger d;

    public AsymmetricDSTU4145PrivateKey(Algorithm algorithm, DSTU4145Parameters parameters, BigInteger s)
    {
        super(algorithm, parameters);

        this.d = s;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricDSTU4145PrivateKey(Algorithm ecAlg, byte[] encoding)
    {
        this(ecAlg, PrivateKeyInfo.getInstance(encoding));
    }

    public AsymmetricDSTU4145PrivateKey(Algorithm ecAlg, PrivateKeyInfo privateKeyInfo)
    {
        super(ecAlg, privateKeyInfo.getPrivateKeyAlgorithm());

        this.privKeyInfo = privateKeyInfo;
        this.d = parsePrivateKey(privateKeyInfo);
        this.hashCode = calculateHashCode();
    }

    private static BigInteger parsePrivateKey(PrivateKeyInfo privateKeyInfo)
    {
        try
        {
            ASN1Encodable privKey = privateKeyInfo.parsePrivateKey();
            if (privKey instanceof ASN1Integer)
            {
                ASN1Integer derD = ASN1Integer.getInstance(privKey);

                return derD.getValue();
            }
            else
            {
                return ECPrivateKey.getInstance(privKey).getKey();
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in DSTU4145 private key");
        }
    }

    public final byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        ECPrivateKey keyStructure;

        if (privKeyInfo != null)
        {
            return KeyUtils.getEncodedInfo(privKeyInfo);
        }
        else
        {
            DSTU4145Parameters dstu4145Parameters = this.getParameters();

            int            orderBitLength = KeyUtils.getOrderBitLength(dstu4145Parameters.getDomainParameters());

            if (dstu4145Parameters.getDomainParameters() instanceof NamedECDomainParameters)
            {
                NamedECDomainParameters namedECDomainParameters = (NamedECDomainParameters)dstu4145Parameters.getDomainParameters();
                DSTU4145Params params = new DSTU4145Params(namedECDomainParameters.getID(), dstu4145Parameters.getDKE());

                keyStructure = new ECPrivateKey(orderBitLength, this.getS(), params);

                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145be, params), keyStructure);
            }
            if (dstu4145Parameters.getDomainParameters().getCurve() instanceof ECCurve.AbstractF2m)
            {
                DSTU4145ECBinary binary = new DSTU4145ECBinary(dstu4145Parameters.getDomainParameters());
                DSTU4145Params params = new DSTU4145Params(binary);

                keyStructure = new ECPrivateKey(orderBitLength, this.getS(), params);

                return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145be, params), keyStructure);
            }
            throw new IllegalArgumentException("Unable to encode binary parameters");
        }
    }

    public BigInteger getS()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        return d;
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricDSTU4145PrivateKey))
        {
            return false;
        }

        AsymmetricDSTU4145PrivateKey other = (AsymmetricDSTU4145PrivateKey)o;

        if (d == null)
        {
            if (other.d != null)
            {
                return false;
            }
        }
        else
        {
            if (!d.equals(other.d))
            {
                return false;
            }
        }

        // we ignore the public point encoding.

        return this.getParameters().equals(other.getParameters());
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = d.hashCode();
        result = 31 * result + this.getParameters().hashCode();
        return result;
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        zeroize();
    }

    private void zeroize()
    {
        this.d = null;
    }
}
