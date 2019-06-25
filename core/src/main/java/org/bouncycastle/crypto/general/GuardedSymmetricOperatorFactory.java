package org.bouncycastle.crypto.general;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InputDecryptor;
import org.bouncycastle.crypto.OperatorUsingSecureRandom;
import org.bouncycastle.crypto.OutputDecryptor;
import org.bouncycastle.crypto.OutputEncryptor;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricOperatorFactory;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.io.CipherInputStream;
import org.bouncycastle.crypto.internal.io.CipherOutputStreamImpl;

abstract class GuardedSymmetricOperatorFactory<T extends Parameters>
    implements SymmetricOperatorFactory<T>
{
    // package protect constructor
    GuardedSymmetricOperatorFactory()
    {
        if (!FipsStatus.isReady())
        {
            throw new FipsUnapprovedOperationError("Module has not entered the ready state.");
        }
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved mode");
        }
    }

    public final OutputEncryptor<T> createOutputEncryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved mode", parameters.getAlgorithm());
        }

        return new OutEncryptor(key, parameters, null);
    }

    public OutputDecryptor<T> createOutputDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved mode", parameters.getAlgorithm());
        }

        final BufferedBlockCipher cipher = createCipher(false, key, parameters, null);

        return new OutputDecryptor<T>()
        {
            public CipherOutputStreamImpl getDecryptingStream(OutputStream out)
            {
                if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                {
                    return new CipherOutputStreamImpl(out, (StreamCipher)cipher.getUnderlyingCipher());
                }

                return new CipherOutputStreamImpl(out, cipher);
            }

            public T getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return cipher.getOutputSize(inputLen);
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return cipher.getUpdateOutputSize(inputLen);
            }
        };
    }

    public final InputDecryptor<T> createInputDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved mode", parameters.getAlgorithm());
        }

        final BufferedBlockCipher cipher = createCipher(false, key, parameters, null);

        return new InputDecryptor<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public InputStream getDecryptingStream(InputStream in)
            {
                if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                {
                    return new CipherInputStream(in, (StreamCipher)cipher.getUnderlyingCipher());
                }

                return new CipherInputStream(in, cipher);
            }
        };
    }

    protected abstract BufferedBlockCipher createCipher(boolean forEncryption, SymmetricKey key, T parameters, SecureRandom random);

    private class OutEncryptor
        implements OutputEncryptor<T>, OperatorUsingSecureRandom<OutputEncryptor<T>>
    {
        private final T parameters;
        private final SymmetricKey key;
        private final BufferedBlockCipher cipher;

        public OutEncryptor(SymmetricKey key, T parameters, SecureRandom random)
        {
            this.key = key;
            this.parameters = parameters;

            cipher = createCipher(true, key, parameters, random);
        }

        public CipherOutputStream getEncryptingStream(OutputStream out)
        {
            if (cipher.getUnderlyingCipher() instanceof StreamCipher)
            {
                return new CipherOutputStreamImpl(out, (StreamCipher)cipher.getUnderlyingCipher());
            }

            return new CipherOutputStreamImpl(out, cipher);
        }

        public OutputEncryptor<T> withSecureRandom(SecureRandom random)
        {
            return new OutEncryptor(key, parameters, random);
        }

        public T getParameters()
        {
            return parameters;
        }

        public int getMaxOutputSize(int inputLen)
        {
            return cipher.getOutputSize(inputLen);
        }

        public int getUpdateOutputSize(int inputLen)
        {
            return cipher.getUpdateOutputSize(inputLen);
        }
    }
}
