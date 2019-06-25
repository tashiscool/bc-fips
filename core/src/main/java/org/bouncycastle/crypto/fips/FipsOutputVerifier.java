package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for a FIPS signature verifier.
 *
 * @param <T> The parameters class for this verifier.
 */
public abstract class FipsOutputVerifier<T extends Parameters>
    implements OutputVerifier<T>
{
    // package protect construction
    FipsOutputVerifier()
    {
    }

    public abstract T getParameters();

    public abstract org.bouncycastle.crypto.UpdateOutputStream getVerifyingStream();

    public abstract boolean isVerified(byte[] signature)
        throws InvalidSignatureException;
}
