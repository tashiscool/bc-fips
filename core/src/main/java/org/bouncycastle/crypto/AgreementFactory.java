package org.bouncycastle.crypto;

/**
 * Interface for factories producing Agreement objects supporting key agreement.
 *
 * @param <T> the type for the parameters for the operator made by this factory.
 */
public interface AgreementFactory<T extends Parameters>
{
    /**
     * Return an initialised agreement set up for the passed in key.
     *
     * @param key the key to base the agreement on.
     * @param parameters agreement parameters.
     * @return an initialised Agreement.
     */
    Agreement<T> createAgreement(AsymmetricPrivateKey key, T parameters);
}
