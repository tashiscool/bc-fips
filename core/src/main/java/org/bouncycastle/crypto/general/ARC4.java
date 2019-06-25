package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for implementations of ARC4 based algorithms.
 */
public final class ARC4
{
    private ARC4()
    {

    }

    /**
     * Raw ARC4 algorithm, can be used for creating general purpose ARC4 keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("ARC4");

    public static final Parameters STREAM = new Parameters();

    private static final EngineProvider ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;
    }

    /**
     * Parameters for ARC4/RC4 cipher modes.
     */
    public static final class Parameters
        extends GeneralParameters
    {
        Parameters()
        {
            super(ALGORITHM);
        }
    }

    /**
     * ARC4/RC4 key generator.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        public KeyGenerator(int keySizeInBits, SecureRandom random)
        {
            this.algorithm = ARC4.ALGORITHM;

            if (invalidKeySize(keySizeInBits))
            {
                throw new IllegalArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: RC4");
            }

            this.keySizeInBits = keySizeInBits;
            this.random = random;
        }

        public SymmetricKey doGenerateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for basic ARC4/RC4 encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedSymmetricStreamOperatorFactory<Parameters>
    {
        @Override
        protected StreamCipher createCipher(boolean forEncryption, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            StreamCipher cipher = ENGINE_PROVIDER.createEngine();

            CipherParameters params = Utils.getKeyParameter(validateKey(key, parameters.getAlgorithm()));

            cipher.init(forEncryption, params);

            return cipher;
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm paramAlgorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (invalidKeySize(keyLength))
        {
            throw new IllegalKeyException("Key the wrong size for ARC4");
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, paramAlgorithm);

        return vKey;
    }

    private static boolean invalidKeySize(int keyLength)
    {
        return keyLength < 40 || keyLength > 2048;
    }

    private static final class EngineProvider
        implements org.bouncycastle.crypto.internal.EngineProvider<ARC4Engine>
    {
        public ARC4Engine createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new ARC4Engine(), new VariantKatTest<ARC4Engine>()
            {
                public void evaluate(ARC4Engine engine)
                {
                    byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
                    byte[] output = Hex.decode("1035d3faeefacf4afea5343bc4e8876c");
                    byte[] tmp = new byte[input.length];

                    KeyParameter key = new KeyParameterImpl(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

                    engine.init(true, key);

                    engine.processBytes(input, 0, input.length, tmp, 0);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }

                    engine.init(false, key);

                    engine.processBytes(tmp, 0, tmp.length, tmp, 0);

                    if (!Arrays.areEqual(input, tmp))
                    {
                        fail("Failed self test on decryption");
                    }
                }
            });
        }
    }
}
