package org.bouncycastle.crypto;

/**
 * Base interface for an output signer.
 *
 * @param <T> the parameters type for the signer.
 */
public interface OutputSigner<T extends Parameters>
{
    /**
     * Return the parameters for this output signer.
     *
     * @return the signer's parameters.
     */
    T getParameters();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a signature. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an UpdateOutputStream
     */
    UpdateOutputStream getSigningStream();

    /**
     * Return the signature calculated on what has been written to the calculator's output stream.
     *
     * @return a signature.
     * @throws PlainInputProcessingException if the input provided cannot be processed.
     */
    byte[] getSignature()
        throws PlainInputProcessingException;

    /**
     * Output the signature  value for what has been written to the signer's output stream.
     *
     * @param output output array to write the signature to.
     * @param off offset to start writing the signature at.
     * @return the number of bytes output.
     * @throws PlainInputProcessingException if the input provided cannot be processed.
     */
    int getSignature(byte[] output, int off)
        throws PlainInputProcessingException;
}
