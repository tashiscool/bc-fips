package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.fips.FipsTripleDES;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Source class for implementations of Pseudo Random Number Generator (PRNG) from X9.31
 */
public final class X931PRNG
{
    private X931PRNG()
    {

    }

    private enum Variations
    {
        Triple_DES_168,
        AES_128,
        AES_192,
        AES_256
    }

    /**
     * X9.31 PRNG - 3-Key TripleDES
     */
    public static final Base Triple_DES_168 = new Base(new GeneralAlgorithm("TRIPLEDES", Variations.Triple_DES_168));

    /**
     * X9.31 PRNG - 128 bit AES
     */
    public static final Base AES_128 = new Base(new GeneralAlgorithm("AES-128", Variations.AES_128));

    /**
     * X9.31 PRNG - 192 bit AES
     */
    public static final Base AES_192 = new Base(new GeneralAlgorithm("AES-192", Variations.AES_192));

    /**
     * X9.31 PRNG - 256 bit AES
     */
    public static final Base AES_256 = new Base(new GeneralAlgorithm("AES-256", Variations.AES_256));

    /**
     * Base for Builder for SecureRandom objects based on the X9.31 PRNG.
     */
    public static class Base
        implements Parameters
    {
        private final GeneralAlgorithm algorithm;

        /**
         * Basic constructor, creates a builder using an EntropySourceProvider based on the default SecureRandom with
         * predictionResistant set to false.
         * <p>
         * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
         * the default SecureRandom does for its generateSeed() call.
         * </p>
         */
        private Base(GeneralAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /**
         * Return a builder using an EntropySourceProvider based on the default SecureRandom with
         * predictionResistant set to false.
         * <p>
         * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
         * the default SecureRandom does for its generateSeed() call.
         * </p>
         * @return a new Builder instance.
         */
        public Builder fromDefaultEntropy()
        {
            SecureRandom entropySource = new SecureRandom();

            return new Builder(algorithm, entropySource, new BasicEntropySourceProvider(entropySource, false), null);
        }

        /**
         * Return a builder with an EntropySourceProvider based on the passed in SecureRandom and the passed in value
         * for prediction resistance.
         * <p>
         * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
         * the passed in SecureRandom does for its generateSeed() call.
         * </p>
         *
         * @param entropySource       a SecureRandom to use as a source of entropy for the PRNG.
         * @param predictionResistant true if the SecureRandom should be regarded as prediction resistant, false otherwise.
         * @return a new builder instance.
         */
        public Builder fromEntropySource(SecureRandom entropySource, boolean predictionResistant)
        {
            return new Builder(algorithm, entropySource, new BasicEntropySourceProvider(entropySource, predictionResistant), null);
        }

        /**
         * Return a builder which makes creates the SecureRandom objects from a specified entropy source provider.
         * <p>
         * <b>Note:</b> If this constructor is used any calls to setSeed() in the resulting SecureRandom will be ignored.
         * </p>
         *
         * @param entropySourceProvider a provider of EntropySource objects.
         * @return a new builder instance.
         */
        public Builder fromEntropySource(EntropySourceProvider entropySourceProvider)
        {
            return new Builder(algorithm, null, entropySourceProvider, null);
        }

        public Algorithm getAlgorithm()
        {
            return algorithm;
        }
    }

    /**
     * Builder for SecureRandom objects based on the X9.31 PRNG.
     */
    public static class Builder
    {
        private final GeneralAlgorithm algorithm;
        private final SecureRandom random;
        private final EntropySourceProvider entropySourceProvider;

        private byte[] dateTimeVector;

        Builder(GeneralAlgorithm algorithm, SecureRandom random, EntropySourceProvider entropySourceProvider, byte[] dateTimeVector)
        {
            this.algorithm = algorithm;
            this.random = random;
            this.entropySourceProvider = entropySourceProvider;
            this.dateTimeVector = dateTimeVector;
        }

        /**
         * Set the dateTime vector to be used with the generator. If this method is not called a vector is calculated based on
         * System.currentTimeMillis().
         *
         * @param dateTimeVector a dateTime vector - needs to be the same size as the block size of the cipher.
         * @return the current Builder instance.
         */
        public Builder setDateTimeVector(byte[] dateTimeVector)
        {
            this.dateTimeVector = Arrays.clone(dateTimeVector);

            return this;
        }

        /**
         * Construct a X9.31 secure random generator using the passed in engine and key. If predictionResistant is true the
         * generator will be reseeded on each request.
         *
         * @param key the block cipher key to initialise algorithm implementation with.
         * @param predictionResistant true if engine to be reseeded on each use, false otherwise.
         * @return a SecureRandom.
         */
        public GeneralSecureRandom build(SymmetricKey key, boolean predictionResistant)
        {
            BlockCipher engine;
            int         keySizeInBits;

            switch (((Variations)algorithm.basicVariation()))
            {
            case AES_128:
                engine = (BlockCipher)FipsRegister.getProvider(FipsAES.ALGORITHM).createEngine();
                keySizeInBits = 128;
                break;
            case AES_192:
                engine = (BlockCipher)FipsRegister.getProvider(FipsAES.ALGORITHM).createEngine();
                keySizeInBits = 192;
                break;
            case AES_256:
                engine = (BlockCipher)FipsRegister.getProvider(FipsAES.ALGORITHM).createEngine();
                keySizeInBits = 256;
                break;
            case Triple_DES_168:
                engine = (BlockCipher)FipsRegister.getProvider(FipsTripleDES.ALGORITHM).createEngine();
                keySizeInBits = 192;
                break;
            default:
                throw new IllegalArgumentException("Unknown algorithm passed to build(): " + algorithm.getName());
            }

            byte[] dtv = dateTimeVector;

            if (dtv == null)
            {
                dtv = new byte[engine.getBlockSize()];
                Pack.longToBigEndian(System.currentTimeMillis(), dtv, 0);
            }

            byte[] keyBytes = PrivilegedUtils.getKeyBytes(key);

            if (keySizeInBits != keyBytes.length * 8)
            {
                throw new IllegalKeyException("FIPS key not correct length - should be " + keyBytes.length + " bytes long.");
            }

            engine.init(true, new KeyParameterImpl(keyBytes));

            ContinuousTestingEntropySource entropySource = new ContinuousTestingEntropySource(entropySourceProvider.get(engine.getBlockSize() * 8));

            return new GeneralSecureRandom(random, new ContinuousTestingPseudoRNG(new X931PseudoRandom(new X931RNG(engine, dtv, entropySource)), null), entropySource, predictionResistant);
        }
    }

//    private static void aesStartUpTest()
//    {
//        SelfTestExecutor.validate(AES_128, FipsAES.ENGINE_PROVIDER, new BasicKatTest<EngineProvider<BlockCipher>>()
//        {
//            public boolean hasTestPassed(EngineProvider<BlockCipher> provider)
//                throws Exception
//            {
//                BlockCipher engine = provider.createEngine();
//
//                engine.init(true, new KeyParameter(Hex.decode("f7d36762b9915f1ed585eb8e91700eb2")));
//
//                X931RNG rng = new X931RNG(engine, Hex.decode("259e67249288597a4d61e7c0e690afae"), new FixedEntropySourceProvider(Hex.decode("35cc0ea481fc8a4f5f05c7d4667233b2"), false).get(128));
//
//                byte[] res = new byte[rng.getBlockSize() / 8];
//
//                rng.generate(res, false);
//
//                return Arrays.areEqual(Hex.decode("15f013af5a8e9df9a8e37500edaeac43"), res);
//            }
//        });
//    }
//
//    private static void tdesStartUpTest()
//    {
//        SelfTestExecutor.validate(Triple_DES_168, FipsTripleDES.ENGINE_PROVIDER, new BasicKatTest<EngineProvider<BlockCipher>>()
//        {
//            public boolean hasTestPassed(EngineProvider<BlockCipher> provider)
//                throws Exception
//            {
//                BlockCipher engine = provider.createEngine();
//
//                engine.init(true, new KeyParameter(Hex.decode("ef16ec643e5db5892cbc6eabba310b3410e6f8759e3e382c")));
//
//                X931RNG rng = new X931RNG(engine, Hex.decode("55df103deaf68dc4"), new FixedEntropySourceProvider(Hex.decode("96d872b9122c5e74"), false).get(64));
//
//                byte[] res = new byte[rng.getBlockSize() / 8];
//
//                rng.generate(res, false);
//
//                return Arrays.areEqual(Hex.decode("9c960bb9662ce6de"), res);
//            }
//        });
//    }
}
