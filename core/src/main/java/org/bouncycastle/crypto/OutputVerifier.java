package org.bouncycastle.crypto;

/**
 * Base interface for an output verifier which can be used to verify a signature against a data stream.
 *
 * @param <T> the parameters type for the verifier.
 */
public interface OutputVerifier<T extends Parameters>
{
    /**
     * Return the parameters for this output verifier.
     *
     * @return the verifier's parameters.
     */
    T getParameters();

    /**
     * Returns a stream that will accept data for the purpose of verifying a previously calculated signature.
     * Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate the data on the fly as well.
     *
     * @return an UpdateOutputStream
     */
    UpdateOutputStream getVerifyingStream();

    /**
     * Return true if the data written to the verifying stream matches the data the signature was calculated against.
     *
     * @param signature the signature to be confirmed.
     * @return true if the data verifies against the signature, false otherwise.
     */
    boolean isVerified(byte[] signature)
        throws InvalidSignatureException;
}
