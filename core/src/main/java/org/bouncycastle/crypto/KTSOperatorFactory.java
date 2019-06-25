package org.bouncycastle.crypto;

/**
 * Base interface for a creator of secret value encapsulators and extractors.
 *
 * @param <T> the parameters type for the encapsulators and extractors we produce.
 */
public interface KTSOperatorFactory<T extends Parameters>
{
    /**
     * Return a generator for making encapsulated secrets, initialized with the passed in keys and parameters.
     *
     * @param key the key to initialize the generator with.
     * @param parameters parameters specifying the characteristics of the generator.
     * @return an initialized generator.
     */
    EncapsulatingSecretGenerator createGenerator(Key key, T parameters);

    /**
     * Return an extractor for processing encapsulated secrets, initialized with the passed in keys and parameters.
     *
     * @param key the key to initialize the generator with.
     * @param parameters parameters specifying the characteristics of the extractor.
     * @return an initialized extractor.
     */
    EncapsulatedSecretExtractor createExtractor(Key key, T parameters);
}
