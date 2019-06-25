package org.bouncycastle.crypto;

/**
 * Base interface for a MAC calculator.
 *
 * @param <T> the parameters type for the MAC calculator.
 */
public interface OutputMACCalculator<T>
{
    /**
     * Return the parameters for this MAC calculator.
     *
     * @return the MAC calculator's parameters.
     */
    T getParameters();

    /**
     * Return the size of the MAC produced by this calculator in bytes.
     *
     * @return MAC length in bytes.
     */
    int getMACSize();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a MAC. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an UpdateOutputStream
     */
    UpdateOutputStream getMACStream();

    /**
     * Return the MAC calculated on what has been written to the calculator's output stream.
     *
     * @return a MAC.
     */
    byte[] getMAC();

    /**
     * Output the current MAC value for what has been written to the calculator's output stream.
     *
     * @param output output array to write the MAC to.
     * @param off offset to start writing the MAC at.
     * @return the number of bytes written
     */
    int getMAC(byte[] output, int off);
    
    /**
     * Reset the calculator back to its initial state.
     */
    void reset();
}
