package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

abstract class BaseAlgorithmParameters
    extends AlgorithmParametersSpi
{
    protected boolean isASN1FormatString(String format)
    {
        return format == null || format.equals("ASN.1");
    }

    protected final <T extends AlgorithmParameterSpec> T engineGetParameterSpec(
        Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new NullPointerException("Argument to getParameterSpec must not be null");
        }

        return (T)localEngineGetParameterSpec(paramSpec);
    }

    protected final void engineInit(byte[] encoding)
        throws IOException
    {
        engineInit(encoding, "ASN.1");
    }

    protected final byte[] engineGetEncoded()
        throws IOException
    {
        return engineGetEncoded("ASN.1");
    }

    protected byte[] engineGetEncoded(
        String format)
        throws IOException
    {
        if (isASN1FormatString(format))
        {
            return localGetEncoded();
        }

        throw new IOException("Unknown parameter format: " + format);
    }

    protected void engineInit(
        byte[] params,
        String format)
        throws IOException
    {
        if (params == null)
        {
            throw new NullPointerException("Encoded parameters cannot be null");
        }

        if (isASN1FormatString(format))
        {
            try
            {
                localInit(params);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new ProvIOException("Parameter parsing failed: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new IOException("Unknown parameter format: " + format);
        }
    }

    protected abstract byte[] localGetEncoded()
        throws IOException;

    protected abstract void localInit(byte[] encoded)
        throws IOException;

    protected abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
        throws InvalidParameterSpecException;
}
