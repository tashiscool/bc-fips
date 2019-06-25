package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.util.Strings;

class ProvECPublicKey
    implements ECPublicKey, ProvKey<AsymmetricECPublicKey>
{
    private static final long serialVersionUID = -569596969144472700L;
    private transient AsymmetricECPublicKey baseKey;

    ProvECPublicKey(
        Algorithm algorithm,
        ECPublicKey key)
    {
        ECDomainParameters domainParameters = ECUtil.convertFromSpec(key.getParams());

        this.baseKey = new AsymmetricECPublicKey(algorithm, domainParameters, ECUtil.convertPoint(domainParameters.getCurve(), key.getW()));
    }

    ProvECPublicKey(
        Algorithm algorithm,
        ECPublicKeySpec keySpec)
    {
        ECDomainParameters domainParameters = ECUtil.convertFromSpec(keySpec.getParams());

        this.baseKey = new AsymmetricECPublicKey(algorithm, domainParameters, ECUtil.convertPoint(domainParameters.getCurve(), keySpec.getW()));
    }

    ProvECPublicKey(
        AsymmetricECPublicKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricECPublicKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return "EC";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public ECParameterSpec getParams()
    {
        return ECUtil.convertToSpec(baseKey.getDomainParameters());
    }

    public ECPoint getW()
    {
        return new ECPoint(baseKey.getW().getAffineXCoord().toBigInteger(), baseKey.getW().getAffineYCoord().toBigInteger());
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("EC Public Key").append(nl);
        buf.append("    X: ").append(baseKey.getW().getAffineXCoord().toBigInteger().toString(16)).append(nl);
        buf.append("    Y: ").append(baseKey.getW().getAffineYCoord().toBigInteger().toString(16)).append(nl);

        return buf.toString();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvECPublicKey))
        {
            return false;
        }

        ProvECPublicKey other = (ProvECPublicKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricECPublicKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }
}
