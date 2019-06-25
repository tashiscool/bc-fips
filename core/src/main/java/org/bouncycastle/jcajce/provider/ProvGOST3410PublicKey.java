package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricGOST3410PublicKey;
import org.bouncycastle.jcajce.interfaces.GOST3410PublicKey;
import org.bouncycastle.jcajce.spec.GOST3410DomainParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410PublicKeySpec;
import org.bouncycastle.util.Strings;

class ProvGOST3410PublicKey
    implements GOST3410PublicKey, ProvKey<AsymmetricGOST3410PublicKey>
{
    private static final long serialVersionUID = -6251023343619275990L;

    private transient AsymmetricGOST3410PublicKey baseKey;

    ProvGOST3410PublicKey(
        Algorithm algorithm,
        GOST3410PublicKey baseKey)
    {
        this.baseKey = new AsymmetricGOST3410PublicKey(algorithm, GOST3410Util.convertToParams(baseKey.getParams()), baseKey.getY());
    }

    ProvGOST3410PublicKey(
        Algorithm algorithm,
        GOST3410PublicKeySpec keySpec)
    {
        this.baseKey = new AsymmetricGOST3410PublicKey(algorithm, GOST3410Util.convertToParams(keySpec.getParams()), keySpec.getY());
    }

    ProvGOST3410PublicKey(
        AsymmetricGOST3410PublicKey baseKey)
    {
        this.baseKey = baseKey;
    }

    public AsymmetricGOST3410PublicKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return "GOST3410";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public BigInteger getY()
    {
        return baseKey.getY();
    }

    public GOST3410ParameterSpec<GOST3410DomainParameterSpec> getParams()
    {
        return GOST3410Util.convertToSpec(baseKey.getParameters());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvGOST3410PublicKey))
        {
            return false;
        }

        ProvGOST3410PublicKey other = (ProvGOST3410PublicKey)o;

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

        baseKey = new AsymmetricGOST3410PublicKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("GOST3410 Public Key").append(nl);
        buf.append("    Y: ").append(this.getY().toString(16)).append(nl);

        return buf.toString();
    }
}
