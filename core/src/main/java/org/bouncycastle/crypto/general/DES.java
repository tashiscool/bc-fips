package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.ParametersWithIV;
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
 * Source class for implementations of DES based algorithms.
 */
public final class DES
{
    private DES()
    {

    }

    /**
     * Raw DES algorithm, can be used for creating general purpose DES keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("DES");
    
    private static final EngineProvider ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;
    }

    /**
     * DES in electronic code book (ECB) mode.
     */
    public static final Parameters ECB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB));

    /**
     * DES in electronic code book mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters ECBwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.PKCS7));

    /**
     * DES in electronic code book mode with ISO10126-2 padding.
     */
    public static final Parameters ECBwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO10126_2));

    /**
     * DES in electronic code book mode with X9.23 padding.
     */
    public static final Parameters ECBwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.X923));

    /**
     * DES in electronic code book mode with ISO7816-4 padding.
     */
    public static final Parameters ECBwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO7816_4));

    /**
     * DES in electronic code book mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters ECBwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.TBC));

    /**
     * DES in cipher block chaining (CBC) mode.
     */
    public static final Parameters CBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC));

    /**
     * DES in cipher block chaining mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters CBCwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.PKCS7));

    /**
     * DES in cipher block chaining mode with ISO10126-2 padding.
     */
    public static final Parameters CBCwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO10126_2));

    /**
     * DES in cipher block chaining mode with X9.23 padding.
     */
    public static final Parameters CBCwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.X923));

    /**
     * DES in cipher block chaining mode with ISO7816-4 padding.
     */
    public static final Parameters CBCwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO7816_4));

    /**
     * DES in cipher block chaining mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters CBCwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.TBC));

    /**
     * DES in cipher block chaining mode cipher text stealing type 1.
     */
    public static final Parameters CBCwithCS1 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS1));

    /**
     * DES in cipher block chaining mode cipher text stealing type 2.
     */
    public static final Parameters CBCwithCS2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS2));

    /**
     * DES in cipher block chaining mode cipher text stealing type 3.
     */
    public static final Parameters CBCwithCS3 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS3));

    /**
     * DES in cipher feedback (CFB) mode, 8 bit block size.
     */
    public static final Parameters CFB8 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB8));

    /**
     * DES in cipher feedback (CFB) mode, 64 bit block size.
     */
    public static final Parameters CFB64 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB64));

    /**
     * DES in output feedback (OFB) mode, 64 bit block size.
     */
    public static final Parameters OFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OFB64));

    /**
     * DES in counter (CTR) mode.
     */
    public static final Parameters CTR = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CTR));

    /**
     * DES in EAX mode..
     */
    public static final AuthParameters EAX = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.EAX));

    /**
     * DES in OpenPGP cipher feedback (CFB) mode.
     */
    public static final Parameters OpenPGPCFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OpenPGPCFB));

    /**
     * DES cipher-based MAC algorithm.
     */
    public static final AuthParameters CMAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CMAC));

    /**
     * DES  CBC-MAC.
     */
    public static final AuthParameters CBC_MAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CBCMAC));

    /**
     * DES CBC-MAC with ISO7816-4 Padding.
     */
    public static final AuthParameters CBC_MACwithISO7816_4 = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CBCMAC, Padding.ISO7816_4));

    /**
     * DES ISO9797 MAC Algorithm 3
     */
    public static final AuthParameters ISO9797alg3Mac = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.ISO9797alg3));

    /**
     * DES ISO9797 MAC Algorithm 3 with ISO7816-4 Padding
     */
    public static final AuthParameters ISO9797alg3MACwithISO7816_4 = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.ISO9797alg3, Padding.ISO7816_4));

    /**
     * DES  CFB8MAC.
     */
    public static final AuthParameters CFB8_MAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB8MAC));

    /**
     * Parameters for general DES block cipher modes.
     */
    public static final class Parameters
        extends GeneralParameters<GeneralAlgorithm>
        implements ParametersWithIV
    {
        final private byte[] iv;

        Parameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        private Parameters(GeneralAlgorithm algorithm, byte[] iv)
        {
            super(algorithm);

            ((Mode)algorithm.basicVariation()).checkIv(iv, 8);

            this.iv = iv;
        }

        public Parameters withIV(byte[] iv)
        {
            return new Parameters(this.getAlgorithm(), Arrays.clone(iv));
        }

        public Parameters withIV(SecureRandom random)
        {
            return new Parameters(this.getAlgorithm(), this.getAlgorithm().createDefaultIvIfNecessary(8, random));
        }

        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }
    }

    /**
     * Parameters for DES AEAD and MAC modes..
     */
    public static final class AuthParameters
        extends GeneralAuthParameters<AuthParameters>
    {
        private AuthParameters(GeneralAlgorithm algorithm, byte[] iv, int tagLenInBits)
        {
            super(algorithm, 8, iv, tagLenInBits);
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
     * DES key generator.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        public KeyGenerator(SecureRandom random)
        {
            this(ALGORITHM, 56, random);
        }

        public KeyGenerator(GeneralParameters algorithm, int keySizeInBits, SecureRandom random)
        {
            this((GeneralAlgorithm)algorithm.getAlgorithm(), keySizeInBits, random);
        }

        private KeyGenerator(GeneralAlgorithm algorithm, int keySizeInBits, SecureRandom random)
        {
            this.algorithm = algorithm;
            this.keySizeInBits = keySizeInBits;
            this.random = random;
        }

        public SymmetricKey doGenerateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new DesKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for basic DES encryption/decryption operators.
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
     * Factory for DES AEAD encryption/decryption operators.
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
     * Factory for producing DES MAC calculators.
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

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, GeneralAlgorithm paramAlgorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (keyLength != 64)
        {
            if (paramAlgorithm.basicVariation() != Mode.ISO9797alg3)
            {
                throw new IllegalKeyException("DES key must be of length 64 bits including parity");
            }
            else
            {
                if (keyLength != 128 && keyLength != 192)
                {
                    throw new IllegalKeyException("DES key for ISO979alg3 must be of length 128 or 192 bits including parity");
                }
            }
        }
        else
        {
            if (paramAlgorithm.basicVariation() == Mode.ISO9797alg3)
            {
                throw new IllegalKeyException("DES key for ISO979alg3 must be of length 128 or 192 bits including parity");
            }
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, paramAlgorithm);

        return vKey;
    }

    private static final class EngineProvider
        implements org.bouncycastle.crypto.internal.EngineProvider<BlockCipher>
    {
        public BlockCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new DesEngine(), new VariantKatTest<DesEngine>()
            {
                public void evaluate(DesEngine engine)
                {
                    byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
                    byte[] output = Hex.decode("e7109a793167d69a0e62538ba866f7f8");
                    byte[] tmp = new byte[input.length];

                    KeyParameter key = new KeyParameterImpl(Hex.decode("1011121314151617"));

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
