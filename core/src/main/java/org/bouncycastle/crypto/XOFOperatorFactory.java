package org.bouncycastle.crypto;

/**
 * Base interface for a creator of extendable output function (XOF) calculators.
 *
 * @param <T> the parameters type for the XOF calculator we produce.
 */
public interface XOFOperatorFactory<T>
{
    /**
     * Create an extendable output function calculator which provides an OutputStream to write data to.
     *
     * @param parameters configuration parameters for the function.
     * @return an XOF calculator.
     */
    OutputXOFCalculator<T> createOutputXOFCalculator(T parameters);
}
