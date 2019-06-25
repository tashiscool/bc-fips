package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricECGOST3410PrivateKey;
import org.bouncycastle.jcajce.interfaces.ECGOST3410PrivateKey;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;
import org.bouncycastle.jcajce.spec.ECGOST3410PrivateKeySpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.util.Strings;

class ProvECGOST3410PrivateKey
    implements ECGOST3410PrivateKey, ProvKey<AsymmetricECGOST3410PrivateKey>
{
    private static final long serialVersionUID = 7245981689601667138L;

    private transient AsymmetricECGOST3410PrivateKey baseKey;

    ProvECGOST3410PrivateKey(
        Algorithm algorithm,
        ECGOST3410PrivateKey key)
     {
         GOST3410ParameterSpec<ECDomainParameterSpec> params = key.getParams();

         this.baseKey = new AsymmetricECGOST3410PrivateKey(algorithm, GOST3410Util.convertToECParams(params), key.getS());
     }

    ProvECGOST3410PrivateKey(
        Algorithm algorithm,
        ECGOST3410PrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricECGOST3410PrivateKey(algorithm, GOST3410Util.convertToECParams(keySpec.getParams()), keySpec.getS());
    }

    ProvECGOST3410PrivateKey(
        AsymmetricECGOST3410PrivateKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricECGOST3410PrivateKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return baseKey.getAlgorithm().getName();
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public GOST3410ParameterSpec<ECDomainParameterSpec> getParams()
    {
        return GOST3410Util.convertToECSpec(baseKey.getParameters());
    }

    public BigInteger getS()
    {
        return baseKey.getS();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvECGOST3410PrivateKey))
        {
            return false;
        }

        ProvECGOST3410PrivateKey other = (ProvECGOST3410PrivateKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("ECGOST3410 Private Key").append(nl);
        try
        {
            buf.append("    S: ").append(this.getS().toString(16)).append(nl);
        }
        catch (Exception e)
        {
            buf.append("RESTRICTED").append(nl);
        }

        return buf.toString();

    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricECGOST3410PrivateKey(alg, enc);
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
