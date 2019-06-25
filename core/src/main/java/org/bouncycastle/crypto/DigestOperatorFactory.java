package org.bouncycastle.crypto;

/**
 * Interface describing an operator factory for creating digest calculators.
 *
 * @param <T> the type for the parameters for the operator made by this factory.
 */
public interface DigestOperatorFactory<T extends Parameters>
{
    /**
     * Return a calculator for a particular digest.
     *
     * @param parameter the parameters for this calculator.
     * @return a digest calculator that provides an OutputStream to enter data.
     */
    OutputDigestCalculator<T> createOutputDigestCalculator(final T parameter);
}
