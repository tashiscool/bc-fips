package org.bouncycastle.crypto;

/**
 * Base interface for a digest calculator.
 *
 * @param <T> the parameters type for the digest calculator.
 */
public interface OutputDigestCalculator<T>
    extends Cloneable
{
    /**
     * Return the parameters for this digest calculator.
     *
     * @return the digest calculator's parameters.
     */
    T getParameters();

    /**
     * Return the size of the digest produced by this calculator in bytes.
     *
     * @return digest length in bytes.
     */
    int getDigestSize();

    /**
     * Return the size, in bytes, of the internal block used by the digest in this calculator.
     *
     * @return internal block size in bytes.
     */
    int getDigestBlockSize();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a digest. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    UpdateOutputStream getDigestStream();

    /**
     * Return the digest calculated on what has been written to the calculator's output stream.
     *
     * @return a digest.
     */
    byte[] getDigest();

    /**
     * Output the current digest value for what has been written to the calculator's output stream.
     *
     * @param output output array to write the digest to.
     * @param off offset to start writing the digest at..
     * @return the number of bytes written.
     */
    int getDigest(byte[] output, int off);

    /**
     * Reset the calculator back to its initial state.
     */
    void reset();

    /**
     * Return a clone of this calculator.
     *
     * @return a clone of the digest calculator.
     * @throws CloneNotSupportedException if cloning is not possible.
     */
    OutputDigestCalculator<T> clone()
        throws CloneNotSupportedException;
}
