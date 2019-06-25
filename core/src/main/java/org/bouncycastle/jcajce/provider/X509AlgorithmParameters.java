package org.bouncycastle.jcajce.provider;

import java.io.IOException;

abstract class X509AlgorithmParameters
    extends BaseAlgorithmParameters
{
    protected final byte[] engineGetEncoded(
        String format)
        throws IOException
    {
        if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509"))
        {
            return localGetEncoded();
        }

        throw new IOException("Unknown parameter format: " + format);
    }

    protected final void engineInit(
        byte[] params,
        String format)
        throws IOException
    {
        if (params == null)
        {
            throw new NullPointerException("Encoded parameters cannot be null");
        }

        if (isASN1FormatString(format) || format.equals("X.509"))
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
}
