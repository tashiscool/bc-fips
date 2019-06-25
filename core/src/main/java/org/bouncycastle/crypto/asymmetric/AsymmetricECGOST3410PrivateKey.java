package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;

/**
 * Class for keys for GOST R 34.10-2001 (ECGOST) private keys.
 */
public final class AsymmetricECGOST3410PrivateKey
    extends AsymmetricGOST3410Key<ECDomainParameters>
    implements AsymmetricPrivateKey
{
    private final int hashCode;

    private BigInteger x;

    public AsymmetricECGOST3410PrivateKey(Algorithm algorithm, GOST3410Parameters<ECDomainParameters> params, BigInteger x)
    {
        super(algorithm, params);

        this.x = x;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricECGOST3410PrivateKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, PrivateKeyInfo.getInstance(enc));
    }

    public AsymmetricECGOST3410PrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
    {
        super(algorithm, CryptoProObjectIdentifiers.gostR3410_2001, privateKeyInfo.getPrivateKeyAlgorithm());

        this.x = parsePrivateKey(privateKeyInfo);
        this.hashCode = calculateHashCode();
    }

    private static BigInteger parsePrivateKey(PrivateKeyInfo info)
    {
        try
        {
            ASN1Encodable keyData = info.parsePrivateKey();

            if (keyData instanceof ASN1Integer)
            {
                return ASN1Integer.getInstance(keyData).getPositiveValue();
            }
            else
            {
                byte[] encVal = ASN1OctetString.getInstance(keyData).getOctets();
                byte[] dVal = new byte[encVal.length];

                for (int i = 0; i != encVal.length; i++)
                {
                    dVal[i] = encVal[encVal.length - 1 - i];
                }

                return new BigInteger(1, dVal);
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse ECGOST3410 private key: " + e.getMessage(), e);
        }
    }

    public final byte[] getEncoded()
    {
        byte[] encKey = new byte[32];

        extractBytes(encKey, 0, this.getS());

        if (getParameters().getPublicKeyParamSet() != null)
        {
            GOST3410PublicKeyAlgParameters pubParams = new GOST3410PublicKeyAlgParameters(getParameters().getPublicKeyParamSet(), getParameters().getDigestParamSet(), getParameters().getEncryptionParamSet());

            return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, pubParams), new DEROctetString(encKey));
        }
        else
        {
            return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001), new DEROctetString(encKey));
        }
    }

    private void extractBytes(byte[] encKey, int offSet, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        if (val.length < 32)
        {
            byte[] tmp = new byte[32];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != 32; i++)
        {
            encKey[offSet + i] = val[val.length - 1 - i];
        }
    }

    public BigInteger getS()
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

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricECGOST3410PrivateKey))
        {
            return false;
        }

        AsymmetricECGOST3410PrivateKey other = (AsymmetricECGOST3410PrivateKey)o;

        return x.equals(other.x) && this.getParameters().equals(other.getParameters());
    }
}
