package org.bouncycastle.crypto;

/**
 * Base interface for an eXtendable Output Funnction (XOF) calculator.
 *
 * @param <T> the parameters type for the XOF calculator.
 */
public interface OutputXOFCalculator<T>
{
    /**
     * Return the parameters for this MAC calculator.
     *
     * @return the MAC calculator's parameters.
     */
    T getParameters();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a MAC. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an UpdateOutputStream
     */
    UpdateOutputStream getFunctionStream();

    /**
     * Return the outLen bytes of function output for what has been written to the calculator's output stream.
     *
     * @param outLen the number of output bytes requested.
     * @return a byte array containing outLen bytes of output.
     */
    byte[] getFunctionOutput(int outLen);

    /**
     * Output the function output for what has been written to the calculator's output stream.
     *
     * @param output output array to write the output bytes to.
     * @param off offset to start writing the bytes at.
     * @param outLen the number of output bytes requested.
     * @return the number of bytes written
     */
    int getFunctionOutput(byte[] output, int off, int outLen);
    
    /**
     * Reset the calculator back to its initial state.
     */
    void reset();
}
