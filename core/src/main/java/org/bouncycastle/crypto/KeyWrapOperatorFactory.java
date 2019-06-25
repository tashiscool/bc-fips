package org.bouncycastle.crypto;

/**
 * Base interface for a creator of key wrappers and un-wrappers.
 *
 * @param <T> the parameter type for the key wrappers/un-wrappers we produce.
 */
public interface KeyWrapOperatorFactory<T extends Parameters, K extends Key>
{
    /**
     * Create a key wrapper using the passed in key and parameters.
     *
     * @param key the key to initialize the wrapper with.
     * @param parameters the parameters to initialize the wrapper with.
     * @return an initialized key wrapper.
     */
    KeyWrapper<T> createKeyWrapper(K key, T parameters);

    /**
     * Create a key un-wrapper using the passed in key and parameters.
     *
     * @param key the key to initialize the un-wrapper with.
     * @param parameters the parameters to initialize the un-wrapper with.
     * @return an initialized key un-wrapper.
     */
    KeyUnwrapper<T> createKeyUnwrapper(K key, T parameters);
}
