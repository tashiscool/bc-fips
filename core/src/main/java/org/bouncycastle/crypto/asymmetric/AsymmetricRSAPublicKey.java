package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;

/**
 * Class for RSA public keys.
 */
public final class AsymmetricRSAPublicKey
    extends AsymmetricRSAKey
    implements AsymmetricPublicKey
{
    private final BigInteger publicExponent;

    public AsymmetricRSAPublicKey(Algorithm algorithm, BigInteger modulus, BigInteger publicExponent)
    {
        super(algorithm, KeyUtils.validated(modulus, publicExponent));

        this.publicExponent = publicExponent;
    }

    public AsymmetricRSAPublicKey(Algorithm algorithm, byte[] publicKeyInfoEncoding)
    {
        this(algorithm, SubjectPublicKeyInfo.getInstance(publicKeyInfoEncoding));
    }

    public AsymmetricRSAPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
    {
        this(algorithm, publicKeyInfo.getAlgorithm(), parsePublicKey(publicKeyInfo));
    }

    private static RSAPublicKey parsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
    {
        try
        {
            return RSAPublicKey.getInstance(publicKeyInfo.parsePublicKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse public key: " + e.getMessage(), e);
        }
    }

    private AsymmetricRSAPublicKey(Algorithm algorithm, AlgorithmIdentifier pubKeyAlgorithm, RSAPublicKey pubKey)
    {
        super(algorithm, pubKeyAlgorithm, KeyUtils.validated(pubKey.getModulus(), pubKey.getPublicExponent()));

        this.publicExponent = pubKey.getPublicExponent();
    }

    public BigInteger getPublicExponent()
    {
        return publicExponent;
    }

    public byte[] getEncoded()
    {
        return KeyUtils.getEncodedSubjectPublicKeyInfo(rsaAlgIdentifier, new RSAPublicKey(getModulus(), getPublicExponent()));
    }

    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(o instanceof AsymmetricRSAPublicKey))
        {
            return false;
        }

        AsymmetricRSAPublicKey other = (AsymmetricRSAPublicKey)o;

        if (!getModulus().equals(other.getModulus()))
        {
            return false;
        }
        if (!publicExponent.equals(other.publicExponent))
        {
            return false;
        }

        return true;
    }

    public int hashCode()
    {
        int result = getModulus().hashCode();
        result = 31 * result + publicExponent.hashCode();
        return result;
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        zeroize();
    }
}
