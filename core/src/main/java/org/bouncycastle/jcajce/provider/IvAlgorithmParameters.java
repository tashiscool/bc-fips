package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;

class IvAlgorithmParameters
    extends BaseAlgorithmParameters
{
    private byte[] iv;

    protected byte[] localGetEncoded()
        throws IOException
    {
        return new DEROctetString(iv).getEncoded();
    }

    protected AlgorithmParameterSpec localEngineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == IvParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
        {
            return new IvParameterSpec(iv);
        }

        throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
    }

    protected void engineInit(
        AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec instanceof IvParameterSpec)
        {
            this.iv = ((IvParameterSpec)paramSpec).getIV();
        }
        else
        {
            throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
        }
    }

    protected void localInit(byte[] params)
        throws IOException
    {
        try
        {
            ASN1OctetString oct = (ASN1OctetString)ASN1Primitive.fromByteArray(params);

            this.iv = oct.getOctets();
        }
        catch (Exception e)
        {
            throw new IOException("Exception decoding: " + e);
        }
    }

    protected String engineToString()
    {
        return "IV Parameters";
    }
}
