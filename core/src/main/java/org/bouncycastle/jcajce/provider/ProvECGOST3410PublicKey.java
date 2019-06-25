package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricECGOST3410PublicKey;
import org.bouncycastle.jcajce.interfaces.ECGOST3410PublicKey;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;
import org.bouncycastle.jcajce.spec.ECGOST3410PublicKeySpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.util.Strings;

class ProvECGOST3410PublicKey
    implements ECGOST3410PublicKey, ProvKey<AsymmetricECGOST3410PublicKey>
{
    private static final long serialVersionUID = 7026240464295649314L;

    private transient AsymmetricECGOST3410PublicKey baseKey;

    ProvECGOST3410PublicKey(
        Algorithm algorithm,
        ECGOST3410PublicKey key)
    {
        GOST3410ParameterSpec<ECDomainParameterSpec> params = key.getParams();

        this.baseKey = new AsymmetricECGOST3410PublicKey(algorithm, GOST3410Util.convertToECParams(params), ECUtil.convertPoint(params.getDomainParametersSpec(), key.getW()));
    }


    ProvECGOST3410PublicKey(
        Algorithm algorithm,
        ECGOST3410PublicKeySpec keySpec)
    {
        GOST3410ParameterSpec<ECDomainParameterSpec> params = keySpec.getParams();

        this.baseKey = new AsymmetricECGOST3410PublicKey(algorithm,  GOST3410Util.convertToECParams(params), ECUtil.convertPoint(params.getDomainParametersSpec(), keySpec.getW()));
    }

    ProvECGOST3410PublicKey(
        AsymmetricECGOST3410PublicKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricECGOST3410PublicKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return baseKey.getAlgorithm().getName();
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public GOST3410ParameterSpec<ECDomainParameterSpec> getParams()
    {
        return GOST3410Util.convertToECSpec(baseKey.getParameters());
    }

    public ECPoint getW()
    {
        return new ECPoint(baseKey.getW().getAffineXCoord().toBigInteger(), baseKey.getW().getAffineYCoord().toBigInteger());
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("ECGOST3410 Public Key").append(nl);
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

        if (!(o instanceof ProvECGOST3410PublicKey))
        {
            return false;
        }

        ProvECGOST3410PublicKey other = (ProvECGOST3410PublicKey)o;

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

        baseKey = new AsymmetricECGOST3410PublicKey(alg, enc);
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
