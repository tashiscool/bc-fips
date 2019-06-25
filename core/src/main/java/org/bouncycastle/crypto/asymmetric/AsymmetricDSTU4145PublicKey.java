package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ua.DSTU4145ECBinary;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Class for DSTU-4145 public keys.
 */
public final class AsymmetricDSTU4145PublicKey
    extends AsymmetricDSTU4145Key
    implements AsymmetricPublicKey
{
    private ECPoint w;

    public AsymmetricDSTU4145PublicKey(Algorithm algorithm, DSTU4145Parameters params, ECPoint w)
    {
        super(algorithm, params);

        this.w = KeyUtils.validated(w);
    }

    public AsymmetricDSTU4145PublicKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, SubjectPublicKeyInfo.getInstance(enc));
    }

    public AsymmetricDSTU4145PublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
    {
        super(algorithm, publicKeyInfo.getAlgorithm());

        this.w = KeyUtils.validated(parsePublicKey(getParameters(), publicKeyInfo));
    }

    private static ECPoint parsePublicKey(DSTU4145Parameters dstu4145Parameters, SubjectPublicKeyInfo publicKeyInfo)
    {
        try
        {
            ASN1OctetString key = ASN1OctetString.getInstance(publicKeyInfo.parsePublicKey());

            byte[] keyEnc = key.getOctets();

            if (publicKeyInfo.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
            {
                reverseBytes(keyEnc);
            }

            return DSTU4145PointEncoder.decodePoint(dstu4145Parameters.getDomainParameters().getCurve(), keyEnc);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Invalid info structure in DSTU4145 public key");
        }
    }

    public ECPoint getW()
    {
        return w;
    }

    public byte[] getEncoded()
    {
        if (dstu4145Identifier != null)
        {
            byte[] encKey = DSTU4145PointEncoder.encodePoint(this.w);

            if (dstu4145Identifier.getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
            {
                reverseBytes(encKey);
            }

            return KeyUtils.getEncodedSubjectPublicKeyInfo(dstu4145Identifier, new DEROctetString(encKey));
        }
        else
        {
            DSTU4145Parameters dstu4145Parameters = this.getParameters();

            ASN1Encodable params;
            if (dstu4145Parameters.getDomainParameters() instanceof NamedECDomainParameters)
            {
                NamedECDomainParameters namedECDomainParameters = (NamedECDomainParameters)dstu4145Parameters.getDomainParameters();

                params = new DSTU4145Params(namedECDomainParameters.getID(), dstu4145Parameters.getDKE());

                byte[] encKey = DSTU4145PointEncoder.encodePoint(this.w);

                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145be, params), new DEROctetString(encKey));
            }
            else
            {
                if (dstu4145Parameters.getDomainParameters().getCurve() instanceof ECCurve.AbstractF2m)
                {
                    DSTU4145ECBinary binary = new DSTU4145ECBinary(dstu4145Parameters.getDomainParameters());

                    byte[] encKey = DSTU4145PointEncoder.encodePoint(this.w);

                    return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145be, new DSTU4145Params(binary)), new DEROctetString(encKey));
                }
                throw new IllegalArgumentException("Unable to encode binary parameters");
            }
        }
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (o instanceof AsymmetricDSTU4145PublicKey)
        {
            AsymmetricDSTU4145PublicKey other = (AsymmetricDSTU4145PublicKey)o;

            return w.equals(other.w) && this.getParameters().equals(other.getParameters());
        }

        return false;
    }

    @Override
    public int hashCode()
    {
        int result = w.hashCode();
        result = 31 * result + this.getParameters().hashCode();
        return result;
    }
}
