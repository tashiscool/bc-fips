package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricGOST3410PrivateKey;
import org.bouncycastle.jcajce.interfaces.GOST3410PrivateKey;
import org.bouncycastle.jcajce.spec.GOST3410DomainParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410PrivateKeySpec;
import org.bouncycastle.util.Strings;

class ProvGOST3410PrivateKey
    implements GOST3410PrivateKey, ProvKey<AsymmetricGOST3410PrivateKey>
{
    private static final long serialVersionUID = 8581661527592305464L;

    private transient AsymmetricGOST3410PrivateKey baseKey;

    ProvGOST3410PrivateKey(
        Algorithm algorithm,
        GOST3410PrivateKey key)
     {
         this.baseKey = new AsymmetricGOST3410PrivateKey(algorithm, GOST3410Util.convertToParams(key.getParams()), key.getX());
     }

    ProvGOST3410PrivateKey(
        Algorithm algorithm,
        GOST3410PrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricGOST3410PrivateKey(algorithm, GOST3410Util.convertToParams(keySpec.getParams()), keySpec.getX());
    }

    ProvGOST3410PrivateKey(
        AsymmetricGOST3410PrivateKey key)
    {
        this.baseKey = key;
    }

    public BigInteger getX()
    {
        return baseKey.getX();
    }

    public GOST3410ParameterSpec<GOST3410DomainParameterSpec> getParams()
    {
        return GOST3410Util.convertToSpec(baseKey.getParameters());
    }

    public AsymmetricGOST3410PrivateKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return "GOST3410";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvGOST3410PrivateKey))
        {
            return false;
        }

        ProvGOST3410PrivateKey other = (ProvGOST3410PrivateKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("GOST3410 Private Key").append(nl);
        try
        {
            buf.append("    X: ").append(this.getX().toString(16)).append(nl);
        }
        catch (Exception e)
        {
            buf.append("RESTRICTED").append(nl);
        }

        return buf.toString();

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

        baseKey = new AsymmetricGOST3410PrivateKey(alg, enc);
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
