package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for implementations of Blowfish based algorithms.
 */
public final class Blowfish
{
    private Blowfish()
    {

    }

    /**
     * Raw Blowfish algorithm, can be used for creating general purpose Blowfish keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("Blowfish");

    private static final EngineProvider ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;
    }

    /**
     * Blowfish in electronic code book (ECB) mode.
     */
    public static final Parameters ECB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB));

    /**
     * Blowfish in electronic code book mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters ECBwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.PKCS7));

    /**
     * Blowfish in electronic code book mode with ISO10126-2 padding.
     */
    public static final Parameters ECBwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO10126_2));

    /**
     * Blowfish in electronic code book mode with X9.23 padding.
     */
    public static final Parameters ECBwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.X923));

    /**
     * Blowfish in electronic code book mode with ISO7816-4 padding.
     */
    public static final Parameters ECBwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO7816_4));

    /**
     * Blowfish in electronic code book mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters ECBwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.TBC));

    /**
     * Blowfish in cipher block chaining (CBC) mode.
     */
    public static final Parameters CBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC));

    /**
     * Blowfish in cipher block chaining mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters CBCwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.PKCS7));

    /**
     * Blowfish in cipher block chaining mode with ISO10126-2 padding.
     */
    public static final Parameters CBCwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO10126_2));

    /**
     * Blowfish in cipher block chaining mode with X9.23 padding.
     */
    public static final Parameters CBCwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.X923));

    /**
     * Blowfish in cipher block chaining mode with ISO7816-4 padding.
     */
    public static final Parameters CBCwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO7816_4));

    /**
     * Blowfish in cipher block chaining mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters CBCwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.TBC));

    /**
     * Blowfish in cipher block chaining mode cipher text stealing type 1.
     */
    public static final Parameters CBCwithCS1 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS1));

    /**
     * Blowfish in cipher block chaining mode cipher text stealing type 2.
     */
    public static final Parameters CBCwithCS2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS2));

    /**
     * Blowfish in cipher block chaining mode cipher text stealing type 3.
     */
    public static final Parameters CBCwithCS3 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS3));

    /**
     * Blowfish in cipher feedback (CFB) mode, 8 bit block size.
     */
    public static final Parameters CFB8 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB8));

    /**
     * Blowfish in cipher feedback (CFB) mode, 64 bit block size.
     */
    public static final Parameters CFB64 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB64));

    /**
     * Blowfish in output feedback (OFB) mode.
     */
    public static final Parameters OFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OFB64));

    /**
     * Blowfish in counter (CTR) mode.
     */
    public static final Parameters CTR = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CTR));

    /**
     * Blowfish in EAX mode..
     */
    public static final AuthParameters EAX = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.EAX));

    /**
     * Blowfish in OpenPGP cipher feedback (CFB) mode.
     */
    public static final Parameters OpenPGPCFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OpenPGPCFB));

    /**
     * Blowfish cipher-based MAC algorithm.
     */
    public static final AuthParameters CMAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CMAC));

    /**
     * Parameters for general Blowfish block cipher modes.
     */
    public static final class Parameters
        extends GeneralParametersWithIV<Parameters>
    {
        private Parameters(GeneralAlgorithm algorithm, byte[] iv)
        {
            super(algorithm, 8, algorithm.checkIv(iv, 8));
        }

        Parameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        protected Parameters create(GeneralAlgorithm algorithm, byte[] iv)
        {
            return new Parameters(algorithm, iv);
        }
    }

    /**
     * Parameters for Blowfish AEAD and MAC modes..
     */
    public static final class AuthParameters
        extends GeneralAuthParameters<AuthParameters>
    {
        private AuthParameters(GeneralAlgorithm algorithm, byte[] iv, int macLenInBits)
        {
            super(algorithm, 8, iv, macLenInBits);
        }

        /**
         * Base constructor - the algorithm, null IV.
         * In this case the tag length defaults to the 64 for CMAC, 32 bits otherwise.
         *
         * @param algorithm algorithm mode.
         */
        AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null, Utils.getDefaultMacSize(algorithm, 64));  // tag full blocksize or half
        }

        protected AuthParameters create(GeneralAlgorithm algorithm, byte[] iv, int macSizeInBits)
        {
            return new AuthParameters(algorithm, iv, macSizeInBits);
        }
    }

    /**
     * Blowfish key generator.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        public KeyGenerator(int keySizeInBits, SecureRandom random)
        {
            this(ALGORITHM, keySizeInBits, random);
        }

        public KeyGenerator(GeneralParameters parameterSet, int keySizeInBits, SecureRandom random)
        {
             this((GeneralAlgorithm)parameterSet.getAlgorithm(), keySizeInBits, random);
        }

        private KeyGenerator(GeneralAlgorithm algorithm, int keySizeInBits, SecureRandom random)
        {
            this.algorithm = algorithm;

            if (invalidKeySize(keySizeInBits))
            {
                throw new IllegalArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: " + algorithm.getName());
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
     * Factory for basic Blowfish encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedSymmetricOperatorFactory<Parameters>
    {
        @Override
        protected BufferedBlockCipher createCipher(boolean forEncryption, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            return CipherUtils.createStandardCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), ENGINE_PROVIDER, parameters, random);
        }
    }

    /**
     * Factory for Blowfish AEAD encryption/decryption operators.
     */
    public static final class AEADOperatorFactory
        extends GuardedAEADOperatorFactory<AuthParameters>
    {
        @Override
        protected AEADBlockCipher createAEADCipher(boolean forEncryption, SymmetricKey key, AuthParameters parameters)
        {
            return CipherUtils.createStandardAEADCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), ENGINE_PROVIDER, parameters);
        }
    }

    /**
     * Factory for producing Blowfish MAC calculators.
     */
    public static final class MACOperatorFactory
        extends GuardedMACOperatorFactory<AuthParameters>
    {
        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            return CipherUtils.createStandardMac(validateKey(key, parameters.getAlgorithm()), ENGINE_PROVIDER, parameters);
        }

        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return Utils.bitsToBytes(parameters.macLenInBits);
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm paramAlgorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (invalidKeySize(keyLength))
        {
            throw new IllegalKeyException("Blowfish key must be between 32 and 448 bits inclusive");
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, paramAlgorithm);

        return vKey;
    }

    private static boolean invalidKeySize(int keyLength)
    {
        return keyLength < 32 || keyLength > 448;
    }

    private static final class EngineProvider
        implements org.bouncycastle.crypto.internal.EngineProvider<BlockCipher>
    {
        public BlockCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new BlowfishEngine(), new VariantKatTest<BlowfishEngine>()
            {
                public void evaluate(BlowfishEngine engine)
                {
                    byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
                    byte[] output = Hex.decode("1c6eba2c44705f4b5ade62b53554ae9a");
                    byte[] tmp = new byte[input.length];

                    KeyParameter key = new KeyParameterImpl(Hex.decode("101112131415161718191a1b1c1d1e1f"));

                    engine.init(true, key);

                    engine.processBlock(input, 0, tmp, 0);
                    engine.processBlock(input, 8, tmp, 8);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }

                    engine.init(false, key);

                    engine.processBlock(tmp, 0, tmp, 0);
                    engine.processBlock(tmp, 8, tmp, 8);

                    if (!Arrays.areEqual(input, tmp))
                    {
                        fail("Failed self test on decryption");
                    }
                }
            });
        }
    }
}
