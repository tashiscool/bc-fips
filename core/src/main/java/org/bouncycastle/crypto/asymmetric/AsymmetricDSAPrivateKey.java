package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;

/**
 * Class for Digital Signature Algorithm (DSA) private keys.
 */
public final class AsymmetricDSAPrivateKey
    extends AsymmetricDSAKey
    implements AsymmetricPrivateKey
{
    private final int hashCode;

    private BigInteger x;

    public AsymmetricDSAPrivateKey(Algorithm algorithm, DSADomainParameters params, BigInteger x)
    {
        super(algorithm, params);

        this.x = x;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricDSAPrivateKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, PrivateKeyInfo.getInstance(enc));
    }

    public AsymmetricDSAPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
    {
        super(algorithm, privateKeyInfo.getPrivateKeyAlgorithm());

        this.x = parsePrivateKey(privateKeyInfo);
        this.hashCode = calculateHashCode();
    }

    private static BigInteger parsePrivateKey(PrivateKeyInfo info)
    {
        try
        {
            return ASN1Integer.getInstance(info.parsePrivateKey()).getValue();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse DSA private key: " + e.getMessage(), e);
        }
    }

    public final byte[] getEncoded()
    {
        DSADomainParameters dsaDomainParameters = this.getDomainParameters();

        return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(dsaDomainParameters.getP(), dsaDomainParameters.getQ(), dsaDomainParameters.getG())), new ASN1Integer(getX()));
    }

    public BigInteger getX()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        return x;
    }

    private void zeroize()
    {
        this.x = null;
    }

    @Override
    public int hashCode()
    {
        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = x.hashCode();
        result = 31 * result + this.getDomainParameters().hashCode();
        return result;
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        zeroize();
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricDSAPrivateKey))
        {
            return false;
        }

        AsymmetricDSAPrivateKey other = (AsymmetricDSAPrivateKey)o;

        return x.equals(other.x) && this.getDomainParameters().equals(other.getDomainParameters());
    }
}
