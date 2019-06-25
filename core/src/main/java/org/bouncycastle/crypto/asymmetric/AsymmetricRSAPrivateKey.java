package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;

/**
 * Class for RSA private keys.
 */
public final class AsymmetricRSAPrivateKey
    extends AsymmetricRSAKey
    implements AsymmetricPrivateKey
{
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger p;
    private BigInteger q;
    private BigInteger dp;
    private BigInteger dq;
    private BigInteger qInv;

    private final int hashCode;

    public AsymmetricRSAPrivateKey(Algorithm algorithm, BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger qInv)
    {
        super(algorithm, modulus);

        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qInv = qInv;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricRSAPrivateKey(Algorithm algorithm, BigInteger modulus, BigInteger privateExponent)
    {
        super(algorithm, modulus);

        this.privateExponent = privateExponent;
        this.publicExponent = BigInteger.ZERO;
        this.p = BigInteger.ZERO;
        this.q = BigInteger.ZERO;
        this.dp = BigInteger.ZERO;
        this.dq = BigInteger.ZERO;
        this.qInv = BigInteger.ZERO;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricRSAPrivateKey(Algorithm algorithm, byte[] privateKeyInfoEncoding)
    {
        this(algorithm, getPrivateKeyInfo(privateKeyInfoEncoding));
    }

    public AsymmetricRSAPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
    {
        this(algorithm, privateKeyInfo.getPrivateKeyAlgorithm(), parsePrivateKey(privateKeyInfo));
    }

    private static PrivateKeyInfo getPrivateKeyInfo(byte[] encoding)
    {
        try
        {
            return PrivateKeyInfo.getInstance(encoding);
        }
        catch (IllegalArgumentException e)
        {
            // OpenSSL's old format, and some others - Try just the private key data.
            try
            {
                return new PrivateKeyInfo(DEF_ALG_ID, ASN1Sequence.getInstance(encoding));
            }
            catch (IOException e1)
            {
                throw new IllegalArgumentException("Unable to parse private key: " + e.getMessage(), e);
            }
        }
    }

    private static RSAPrivateKey parsePrivateKey(PrivateKeyInfo privateKeyInfo)
    {
        try
        {
            return RSAPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse private key: " + e.getMessage(), e);
        }
    }

    private AsymmetricRSAPrivateKey(Algorithm algorithm, AlgorithmIdentifier algId, RSAPrivateKey privKey)
    {
        // we're importing from an encoding, let's just make sure the modulus is actually valid.
        super(algorithm, algId, KeyUtils.validatedModulus(privKey.getModulus()));

        this.publicExponent = privKey.getPublicExponent();
        this.privateExponent = privKey.getPrivateExponent();
        this.p = privKey.getPrime1();
        this.q = privKey.getPrime2();
        this.dp = privKey.getExponent1();
        this.dq = privKey.getExponent2();
        this.qInv = privKey.getCoefficient();
        this.hashCode = calculateHashCode();
    }

    public BigInteger getPublicExponent()
    {
        return publicExponent;
    }

    public BigInteger getPrivateExponent()
    {
        checkCanRead();

        return privateExponent;
    }

    public BigInteger getP()
    {
        checkCanRead();

        return p;
    }

    public BigInteger getQ()
    {
        checkCanRead();

        return q;
    }

    public BigInteger getDP()
    {
        checkCanRead();

        return dp;
    }

    public BigInteger getDQ()
    {
        checkCanRead();

        return dq;
    }

    public BigInteger getQInv()
    {
        checkCanRead();

        return qInv;
    }

    public final byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        return KeyUtils.getEncodedPrivateKeyInfo(rsaAlgIdentifier, new RSAPrivateKey(getModulus(), publicExponent, getPrivateExponent(), getP(), getQ(), getDP(), getDQ(), getQInv()));
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }
        if (!(o instanceof AsymmetricRSAPrivateKey))
        {
            return false;
        }

        AsymmetricRSAPrivateKey other = (AsymmetricRSAPrivateKey)o;

        return getModulus().equals(other.getModulus())
            && privateExponent.equals(other.privateExponent) && getPublicExponent().equals(other.getPublicExponent())
            && p.equals(other.p) && q.equals(other.q)
            && dp.equals(other.dp) && dq.equals(other.dq) && qInv.equals(other.qInv);
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = getModulus().hashCode();
        result = 31 * result + publicExponent.hashCode();
        result = 31 * result + privateExponent.hashCode();
        result = 31 * result + p.hashCode();
        result = 31 * result + q.hashCode();
        result = 31 * result + dp.hashCode();
        result = 31 * result + dq.hashCode();
        result = 31 * result + qInv.hashCode();
        return result;
    }

    protected void zeroize()
    {
        this.privateExponent = null;
        this.p = this.q = this.dp = this.dq = this.qInv = null;
        super.zeroize();
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        zeroize();
    }

    private void checkCanRead()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);
    }
}
