package org.bouncycastle.crypto;

/**
 * Base interface for a creator of MAC calculators.
 *
 * @param <T> the parameters type for the MAC calculator we produce.
 */
public interface MACOperatorFactory<T extends AuthenticationParameters>
{
    /**
     * Create a MAC calculator which provides an OutputStream to write data to.
     *
     * @param key the key to use to initialise the MAC.
     * @param parameters any additional parameters.
     * @return a MAC calculator.
     */
    OutputMACCalculator<T> createOutputMACCalculator(SymmetricKey key, T parameters);
}
