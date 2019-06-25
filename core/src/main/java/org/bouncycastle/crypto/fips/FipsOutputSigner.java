package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.PlainInputProcessingException;

/**
 * Base class for a FIPS signature generator..
 *
 * @param <T> The parameters class for this signer.
 */
public abstract class FipsOutputSigner<T extends Parameters>
    implements OutputSigner<T>
{
    // package protect construction
    FipsOutputSigner()
    {
    }

    public abstract T getParameters();

    public abstract org.bouncycastle.crypto.UpdateOutputStream getSigningStream();

    public abstract byte[] getSignature()
        throws PlainInputProcessingException;

    public abstract int getSignature(byte[] output, int off)
        throws PlainInputProcessingException;
}
