package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSTU4145PublicKey;
import org.bouncycastle.jcajce.interfaces.DSTU4145PublicKey;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jcajce.spec.DSTU4145PublicKeySpec;
import org.bouncycastle.util.Strings;

class ProvDSTU4145PublicKey
    implements DSTU4145PublicKey, ProvKey<AsymmetricDSTU4145PublicKey>
{
    private static final long serialVersionUID = 7026240464295649314L;
    private transient AsymmetricDSTU4145PublicKey baseKey;

    ProvDSTU4145PublicKey(
        Algorithm algorithm,
        DSTU4145PublicKey key)
    {
        DSTU4145ParameterSpec params = key.getParams();

        this.baseKey = new AsymmetricDSTU4145PublicKey(algorithm, DSTU4145Util.convertToECParams(params), ECUtil.convertPoint(params, key.getW()));
    }


    ProvDSTU4145PublicKey(
        Algorithm algorithm,
        DSTU4145PublicKeySpec keySpec)
    {
        DSTU4145ParameterSpec params = keySpec.getParams();

        this.baseKey = new AsymmetricDSTU4145PublicKey(algorithm,  DSTU4145Util.convertToECParams(params), ECUtil.convertPoint(params, keySpec.getW()));
    }

    ProvDSTU4145PublicKey(
        AsymmetricDSTU4145PublicKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricDSTU4145PublicKey getBaseKey()
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

    public DSTU4145ParameterSpec getParams()
    {
        return DSTU4145Util.convertToECSpec(baseKey.getParameters());
    }

    public ECPoint getW()
    {
        return new ECPoint(baseKey.getW().getAffineXCoord().toBigInteger(), baseKey.getW().getAffineYCoord().toBigInteger());
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("DSTU4145 Public Key").append(nl);
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

        if (!(o instanceof ProvDSTU4145PublicKey))
        {
            return false;
        }

        ProvDSTU4145PublicKey other = (ProvDSTU4145PublicKey)o;

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

        baseKey = new AsymmetricDSTU4145PublicKey(alg, enc);
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
