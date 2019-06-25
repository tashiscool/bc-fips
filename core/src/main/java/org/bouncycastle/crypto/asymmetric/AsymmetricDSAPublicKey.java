package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;

/**
 * Class for Digital Signature Algorithm (DSA) public keys.
 */
public final class AsymmetricDSAPublicKey
    extends AsymmetricDSAKey
    implements AsymmetricPublicKey
{
    private BigInteger y;

    public AsymmetricDSAPublicKey(Algorithm algorithm, DSADomainParameters params, BigInteger y)
    {
        super(algorithm, params);

        this.y = KeyUtils.validated(params, y);
    }

    public AsymmetricDSAPublicKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, SubjectPublicKeyInfo.getInstance(enc));
    }

    public AsymmetricDSAPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
    {
        super(algorithm, publicKeyInfo.getAlgorithm());

        this.y = KeyUtils.validated(getDomainParameters(), parsePublicKey(publicKeyInfo));
    }

    private static BigInteger parsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
    {
        ASN1Integer derY;

        try
        {
            derY = ASN1Integer.getInstance(publicKeyInfo.parsePublicKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in DSA public key");
        }

        return derY.getValue();
    }

    public BigInteger getY()
    {
        return y;
    }

    public byte[] getEncoded()
    {
        DSADomainParameters domainParameters = getDomainParameters();

        if (getDomainParameters() == null)
        {
            return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa), new ASN1Integer(y));
        }

        return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG()).toASN1Primitive()), new ASN1Integer(y));
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricDSAPublicKey))
        {
            return false;
        }

        AsymmetricDSAPublicKey other = (AsymmetricDSAPublicKey)o;

        if (this.getDomainParameters() != null)
        {
            return y.equals(other.y) && this.getDomainParameters().equals(other.getDomainParameters());
        }
        else
        {
            return y.equals(other.y) && this.getDomainParameters() == other.getDomainParameters();
        }
    }

    @Override
    public int hashCode()
    {
        int result = y.hashCode();

        if (this.getDomainParameters() != null)
        {
            result = 31 * result + this.getDomainParameters().hashCode();
        }

        return result;
    }
}
