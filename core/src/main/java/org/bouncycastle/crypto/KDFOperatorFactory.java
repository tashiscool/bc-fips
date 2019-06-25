package org.bouncycastle.crypto;

/**
 * Interface describing a factory that creates Key Derivation Function (KDF) calculators.
 *
 * @param <T> the type for the parameters for the operator made by this factory.
 */
public interface KDFOperatorFactory<T extends Parameters>
{
    /**
     * Return a calculator for generating bytes for key material.
     *
     * @param params the parameter set to initialize the calculator with.
     * @return a KDF calculator.
     */
    KDFCalculator<T> createKDFCalculator(T params);
}
