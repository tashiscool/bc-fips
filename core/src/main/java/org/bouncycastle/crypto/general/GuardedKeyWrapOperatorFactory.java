package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.Key;
import org.bouncycastle.crypto.KeyUnwrapper;
import org.bouncycastle.crypto.KeyWrapOperatorFactory;
import org.bouncycastle.crypto.KeyWrapper;
import org.bouncycastle.crypto.KeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.Wrapper;

abstract class GuardedKeyWrapOperatorFactory<T extends Parameters, K extends Key>
    implements KeyWrapOperatorFactory<T, K>
{
    // package protect construction
    GuardedKeyWrapOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public KeyWrapper<T> createKeyWrapper(K key, T parameters)
    {
        return new GuardedWrapper(key, parameters, null);
    }

    public KeyUnwrapper<T> createKeyUnwrapper(K key, T parameters)
    {
        return new GuardedUnwrapper(parameters.getAlgorithm(), parameters, createWrapper(false, key, parameters, null));
    }

    protected abstract Wrapper createWrapper(boolean forWrapping, K key, T parameters, SecureRandom random);

    private class GuardedWrapper
        implements KeyWrapperUsingSecureRandom<T>
    {
        private final Algorithm algorithm;
        private final K key;
        private final T parameters;
        private final SecureRandom random;

        private Wrapper wrapper;

        GuardedWrapper(K key, T parameters, SecureRandom random)
        {
            this.algorithm = parameters.getAlgorithm();
            this.key = key;
            this.parameters = parameters;
            this.random = random;
        }

        void setUp()
        {
            if (wrapper == null)
            {
                wrapper = createWrapper(true, key, parameters, random);
            }
        }

        public T getParameters()
        {
            return parameters;
        }

        public byte[] wrap(byte[] in, int inOff, int inLen)
        {
            Utils.approveModeCheck(algorithm);

            setUp();

            return wrapper.wrap(in, inOff, inLen);
        }

        public KeyWrapperUsingSecureRandom<T> withSecureRandom(SecureRandom random)
        {
            return new GuardedWrapper(key, parameters, random);
        }
    }

    private class GuardedUnwrapper
        implements KeyUnwrapper<T>
    {
        private final Algorithm algorithm;
        private final T parameters;
        private final Wrapper wrapper;

        GuardedUnwrapper(Algorithm algorithm, T parameters, Wrapper wrapper)
        {
            this.algorithm = algorithm;
            this.parameters = parameters;
            this.wrapper = wrapper;
        }

        public T getParameters()
        {
            return parameters;
        }

        public byte[] unwrap(byte[] in, int inOff, int inLen)
            throws InvalidWrappingException
        {
            Utils.approveModeCheck(algorithm);

            try
            {
                return wrapper.unwrap(in, inOff, inLen);
            }
            catch (Exception e)
            {
                throw new InvalidWrappingException("Unable to unwrap key: " + e.getMessage(), e);
            }
        }
    }

}
