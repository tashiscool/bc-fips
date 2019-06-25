package org.bouncycastle.crypto.fips;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for FIPS approved implementations of Deterministic Random Bit Generators (DRBGs) from SP 800-90A.
 */
public final class FipsDRBG
{
    // package protect constructor
    private FipsDRBG()
    {

    }

    private enum Variations
    {
        CTR_Triple_DES_168,
        CTR_AES_128,
        CTR_AES_192,
        CTR_AES_256
    }

    /**
     * HASH DRBG - SHA-1
     */
    public static final Base SHA1 = new Base(new FipsAlgorithm("SHA-1", FipsSHS.Variations.SHA1));

    /**
     * HASH DRBG - SHA-224
     */
    public static final Base SHA224 = new Base(new FipsAlgorithm("SHA-224", FipsSHS.Variations.SHA224));

    /**
     * HASH DRBG - SHA-256
     */
    public static final Base SHA256 = new Base(new FipsAlgorithm("SHA-256", FipsSHS.Variations.SHA256));

    /**
     * HASH DRBG - SHA-384
     */
    public static final Base SHA384 = new Base(new FipsAlgorithm("SHA-384", FipsSHS.Variations.SHA384));

    /**
     * HASH DRBG - SHA-512
     */
    public static final Base SHA512 = new Base(new FipsAlgorithm("SHA-512", FipsSHS.Variations.SHA512));

    /**
     * HASH DRBG - SHA-512/224
     */
    public static final Base SHA512_224 = new Base(new FipsAlgorithm("SHA-512(224)", FipsSHS.Variations.SHA512_224));

    /**
     * HASH DRBG - SHA-512/256
     */
    public static final Base SHA512_256 = new Base(new FipsAlgorithm("SHA-512(256)", FipsSHS.Variations.SHA512_256));

    /**
     * HMAC DRBG - SHA-1
     */
    public static final Base SHA1_HMAC = new Base(new FipsAlgorithm("SHA-1/HMAC", FipsSHS.Variations.SHA1_HMAC));

    /**
     * HMAC DRBG - SHA-224
     */
    public static final Base SHA224_HMAC = new Base(new FipsAlgorithm("SHA-224/HMAC", FipsSHS.Variations.SHA224_HMAC));

    /**
     * HMAC DRBG - SHA-256
     */
    public static final Base SHA256_HMAC = new Base(new FipsAlgorithm("SHA-256/HMAC", FipsSHS.Variations.SHA256_HMAC));

    /**
     * HMAC DRBG - SHA-384
     */
    public static final Base SHA384_HMAC = new Base(new FipsAlgorithm("SHA-384/HMAC", FipsSHS.Variations.SHA384_HMAC));

    /**
     * HMAC DRBG - SHA-512
     */
    public static final Base SHA512_HMAC = new Base(new FipsAlgorithm("SHA-512/HMAC", FipsSHS.Variations.SHA512_HMAC));

    /**
     * HMAC DRBG - SHA-512/224
     */
    public static final Base SHA512_224_HMAC = new Base(new FipsAlgorithm("SHA-512(224)/HMAC", FipsSHS.Variations.SHA512_224_HMAC));

    /**
     * HMAC DRBG - SHA-512/256
     */
    public static final Base SHA512_256_HMAC = new Base(new FipsAlgorithm("SHA-512(256)/HMAC", FipsSHS.Variations.SHA512_256_HMAC));

    /**
     * CTR DRBG - 3-Key TripleDES
     */
    public static final Base CTR_Triple_DES_168 = new Base(new FipsAlgorithm("TRIPLEDES", Variations.CTR_Triple_DES_168));

    /**
     * CTR DRBG - 128 bit AES
     */
    public static final Base CTR_AES_128 = new Base(new FipsAlgorithm("AES-128", Variations.CTR_AES_128));

    /**
     * CTR DRBG - 192 bit AES
     */
    public static final Base CTR_AES_192 = new Base(new FipsAlgorithm("AES-192", Variations.CTR_AES_192));

    /**
     * CTR DRBG - 256 bit AES
     */
    public static final Base CTR_AES_256 = new Base(new FipsAlgorithm("AES-256", Variations.CTR_AES_256));

    static
    {
        // FSM_STATE:3.DRBG.0, "DRBG KAT" ,"The module is performing DRBG KAT self-test"
        // FSM_TRANS:3.DRBG.0, "POWER ON SELF-TEST", "DRBG KAT", "Invoke DRBG KAT self-test"
        drbgStartupTest();
        // FSM_TRANS:3.DRBG.1, "DRBG KAT", "POWER ON SELF-TEST", "DRBG KAT self-test successful completion"
    }

    public static class Base
        extends FipsParameters
    {
        Base(FipsAlgorithm algorithm)
        {
            super(algorithm);
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

            return new Builder(getAlgorithm(), entropySource, new BasicEntropySourceProvider(entropySource, false));
        }

        /**
         * Construct a builder with an EntropySourceProvider based on the passed in SecureRandom and the passed in value
         * for prediction resistance.
         * <p>
         * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
         * the passed in SecureRandom does for its generateSeed() call.
         * </p>
         *
         * @param entropySource a source of entropy.
         * @param predictionResistant true if this entropySource is prediction resistant, false otherwise.
         * @return a new Builder instance.
         */
        public Builder fromEntropySource(SecureRandom entropySource, boolean predictionResistant)
        {
            return new Builder(getAlgorithm(), entropySource, new BasicEntropySourceProvider(entropySource, predictionResistant));
        }

        /**
         * Create a builder which makes creates the SecureRandom objects from a specified entropy source provider.
         * <p>
         * <b>Note:</b> If this method is used any calls to setSeed() in the resulting SecureRandom will be ignored.
         * </p>
         *
         * @param entropySourceProvider a provider of EntropySource objects.
         * @return a new Builder instance.
         */
        public Builder fromEntropySource(EntropySourceProvider entropySourceProvider)
        {
            return new Builder(getAlgorithm(), null, entropySourceProvider);
        }
    }

    /**
     * Builder for SecureRandom objects based on the FIPS DRBGs.
     */
    public static class Builder
    {
        private final FipsAlgorithm algorithm;
        private final SecureRandom random;
        private final EntropySourceProvider entropySourceProvider;

        private byte[] personalizationString;
        private int securityStrength = 256;
        private int entropyBitsRequired = 256;

        Builder(FipsAlgorithm algorithm, SecureRandom random, EntropySourceProvider entropySourceProvider)
        {
            FipsStatus.isReady();

            this.algorithm = algorithm;
            this.random = random;
            this.entropySourceProvider = entropySourceProvider;
        }

        /**
         * Set the personalization string for DRBG SecureRandoms created by this builder
         *
         * @param personalizationString the personalisation string for the underlying DRBG.
         * @return the current Builder instance.
         */
        public Builder setPersonalizationString(byte[] personalizationString)
        {
            this.personalizationString = Arrays.clone(personalizationString);

            return this;
        }

        /**
         * Set the security strength required for DRBGs used in building SecureRandom objects.
         *
         * @param securityStrength the security strength (in bits)
         * @return the current Builder instance.
         */
        public Builder setSecurityStrength(int securityStrength)
        {
            this.securityStrength = securityStrength;

            return this;
        }

        /**
         * Set the amount of entropy bits required for seeding and reseeding DRBGs used in building SecureRandom objects.
         *
         * @param entropyBitsRequired the number of bits of entropy to be requested from the entropy source on each seed/reseed.
         * @return the current Builder instance.
         */
        public Builder setEntropyBitsRequired(int entropyBitsRequired)
        {
            this.entropyBitsRequired = entropyBitsRequired;

            return this;
        }

        /**
         * Build a SecureRandom based on a SP 800-90A DRBG.
         *
         * @param nonce               nonce value to use in DRBG construction.
         * @param predictionResistant specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes.
         * @return a SecureRandom supported by a DRBG.
         */
        public FipsSecureRandom build(byte[] nonce, boolean predictionResistant)
        {
            return build(nonce, predictionResistant, null);
        }

        /**
         * Build a SecureRandom based on a SP 800-90A DRBG.
         *
         * @param nonce               nonce value to use in DRBG construction.
         * @param predictionResistant specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes.
         * @param additionalInput     initial additional input to be used for generating the initial continuous health check block by the DRBG.
         * @return a SecureRandom supported by a DRBG.
         */
        public FipsSecureRandom build(byte[] nonce, boolean predictionResistant, byte[] additionalInput)
        {
           return build(algorithm, nonce, predictionResistant, additionalInput);
        }

        private FipsSecureRandom build(FipsAlgorithm algorithm, byte[] nonce, boolean predictionResistant, byte[] additionalInput)
        {
            EntropySource entropySource = entropySourceProvider.get(entropyBitsRequired);
            if (algorithm.basicVariation() instanceof FipsSHS.Variations)
            {
                switch (((FipsSHS.Variations)algorithm.basicVariation()))
                {
                case SHA1:
                case SHA224:
                case SHA256:
                case SHA384:
                case SHA512:
                case SHA512_224:
                case SHA512_256:
                    return new FipsSecureRandom(random, new DRBGPseudoRandom(algorithm, entropySource, new HashDRBGProvider(algorithm, Arrays.clone(nonce), personalizationString, securityStrength, additionalInput)), entropySource, predictionResistant);
                case SHA1_HMAC:
                case SHA224_HMAC:
                case SHA256_HMAC:
                case SHA384_HMAC:
                case SHA512_HMAC:
                case SHA512_224_HMAC:
                case SHA512_256_HMAC:
                    return new FipsSecureRandom(random, new DRBGPseudoRandom(algorithm, entropySource, new HMacDRBGProvider(algorithm, Arrays.clone(nonce), personalizationString, securityStrength, additionalInput)), entropySource, predictionResistant);
                default:
                    throw new IllegalArgumentException("Unknown algorithm passed to build(): " + algorithm.getName());
                }
            }
            else
            {
                BlockCipher cipher;
                int keySizeInBits;

                switch (((Variations)algorithm.basicVariation()))
                {
                case CTR_AES_128:
                    cipher = FipsAES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 128;
                    break;
                case CTR_AES_192:
                    cipher = FipsAES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 192;
                    break;
                case CTR_AES_256:
                    cipher = FipsAES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 256;
                    break;
                case CTR_Triple_DES_168:
                    cipher = FipsTripleDES.ENGINE_PROVIDER.createEngine();
                    keySizeInBits = 168;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown algorithm passed to build(): " + algorithm.getName());
                }

                return new FipsSecureRandom(random, new DRBGPseudoRandom(algorithm, entropySource, new CTRDRBGProvider(cipher, keySizeInBits, Arrays.clone(nonce), personalizationString, securityStrength, additionalInput)), entropySource, predictionResistant);
            }
        }
    }

    private static class HashDRBGProvider
        implements DRBGProvider
    {
        private final Digest digest;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;
        private final byte[] primaryAdditionalInput;

        public HashDRBGProvider(FipsAlgorithm algorithm, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
        {
            FipsStatus.isReady();
            this.digest = FipsSHS.createDigest(algorithm);
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
            this.primaryAdditionalInput = primaryAdditionalInput;
        }

        public DRBG get(EntropySource entropySource)
        {
            HashSP800DRBG drbg = new HashSP800DRBG(digest, securityStrength, entropySource, personalizationString, nonce);

            return new ContinuousTestingPseudoRNG(drbg, primaryAdditionalInput);
        }
    }

    private static class HMacDRBGProvider
        implements DRBGProvider
    {
        private final Mac hMac;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;
        private final byte[] primaryAdditionalInput;

        public HMacDRBGProvider(FipsAlgorithm algorithm, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
        {
            FipsStatus.isReady();
            this.hMac = FipsSHS.createHMac(algorithm);
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
            this.primaryAdditionalInput = primaryAdditionalInput;
        }

        public DRBG get(EntropySource entropySource)
        {
            HMacSP800DRBG drbg = new HMacSP800DRBG(hMac, securityStrength, entropySource, personalizationString, nonce);

            return new ContinuousTestingPseudoRNG(drbg, primaryAdditionalInput);
        }
    }

    private static class CTRDRBGProvider
        implements DRBGProvider
    {
        private final BlockCipher blockCipher;
        private final int keySizeInBits;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;
        private final byte[] primaryAdditionalInput;

        public CTRDRBGProvider(BlockCipher blockCipher, int keySizeInBits, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
        {
            FipsStatus.isReady();
            this.blockCipher = blockCipher;
            this.keySizeInBits = keySizeInBits;
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
            this.primaryAdditionalInput = primaryAdditionalInput;
        }

        public DRBG get(EntropySource entropySource)
        {
            CTRSP800DRBG drbg = new CTRSP800DRBG(blockCipher, keySizeInBits, securityStrength, entropySource, personalizationString, nonce);

            return new ContinuousTestingPseudoRNG(drbg, primaryAdditionalInput);
        }
    }

    private static void drbgStartupTest()
    {
        SelfTestExecutor.validate(
            SHA1.getAlgorithm(), new DRBGHashSelfTest(SHA1.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA1),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    128,
                    new String[]
                        {
                            "532CA1165DCFF21C55592687639884AF4BC4B057DF8F41DE653AB44E2ADEC7C9303E75ABE277EDBF",
                            "73C2C67C696D686D0C4DBCEB5C2AF7DDF6F020B6874FAE4390F102117ECAAFF54418529A367005A0"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA224.getAlgorithm(), new DRBGHashSelfTest(SHA224.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA224),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    192,
                    new String[]
                        {
                            "caa6b14c594ad8c7f701ce3925e7e61838cab688064b259f79f2c5e248c400a1acf0adf8b528c0c6",
                            "2d79081d8bbb32536de24f19976fce1e8557c931135f0d6ddaebb5e85b250804aba7204385f11cdd"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA256.getAlgorithm(), new DRBGHashSelfTest(SHA256.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA256),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "de1c6b0fe66e9106e5203fa821ead509dda22d703434d56a974eb94a47c90ca1e16479c239ab6097",
                            "05bfd156e55000ff68d9c71c6e9d240b385d3f0f52c8f2ba98f35a76104060cc7ee87083501eb159"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA384.getAlgorithm(), new DRBGHashSelfTest(SHA384.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA384),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "ceada7e59f8ca5ebc4ebfa2f7b0a48a198fe514af15c49b8dc10cb36471af2cc8d965f20b9a9c525",
                            "18448b9770c247520ef5e28d04c7b47b71a0e833ea86d247cceaee968785f1b421ae65a57acdc2b5"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA512.getAlgorithm(), new DRBGHashSelfTest(SHA512.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA512),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "3feded5e458d0dd793e59530fb50cf74c5a719d0e93c3d8acc6f864b47929649069dc2fbd515223f",
                            "8acec9a5f42a6e071acd568d4c219a92f125c4eadb570c029340c568d98e2f75c21edd34c82b120a"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA512_224.getAlgorithm(), new DRBGHashSelfTest(SHA512_224.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA512_224),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    192,
                    new String[]
                        {
                            "70c52d78b89c808850af16a3be8bcb3d4841555c9bba77eced34b3b554892ba87f1aa312dfed53c4",
                            "d7f26f260d38144d4994402754810e76b30f8699bbf6b971b2bd79e9f1645be8b6563bc6469dca57"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA512_256.getAlgorithm(), new DRBGHashSelfTest(SHA512_256.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA512_256),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "ce818c49bb4975175db33efd736ae7da12c4d531d5a95f0378cf50adc96d022ad5123d37fe1bf5cf",
                            "96ef76a26d5d31cef4835c3871e391d34e51e73fbb58b2d274a0f3ca9f08da5148de3209863d12a5"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA1_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA1_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA1),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    128,
                    new String[]
                        {
                            "6c37fdd729aa40f80bc6ab08ca7cc649794f6998b57081e4220f22c5c283e2c91b8e305ab869c625",
                            "caf57dcfea393b9236bf691fa456fea7fdf1df8361482ca54d5fa723f4c88b4fa504bf03277fa783"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA224_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA224_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA224),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    192,
                    new String[]
                        {
                            "5bb2b7c488c772f2f1244387e12ababc4cff02240bd29f7b51022e238b07f10c3d5d3fbe42caeb21",
                            "7a30c18cddcfcbc9dee0d107e22d57cf96ffc7d1f7d9eebac2862c256d558734aa22e5f5e6c2a7df"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA256_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA256_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA256),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "2c332d2c6e24fb45d508614d5af3b1cc604b26c5674865557735b6a2900e39227cd467f0cb7ae0d8",
                            "1a3d5fce46b6b3aebe17b8f6421dfd7fa8dcd0429a749d6d3309f07ff31a742a68eb34bf4104f756"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA384_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA384_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA384),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "ec095c82dc870a25ce7b1cdf1e2b88a65cc205255db41b15a70808f122ac83dc4ed64f5c42dcf7e8",
                            "090212d521266e4d6effb79b8f12b629c2b0fea0b4aa0a13fe418c0790bed140585eefbbbc781924"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA512_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA512_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA512),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "7d45419aaa268e9ae7c8c6fde3475a524cd1c41760ec312db2e3a5bb9f6f8405ca62040fd3c2bdda",
                            "3bc3a2956673309dcbde9a7491adc4d4b198e8d558e38dba8a33f1bca74ae0e8a598fca41ecfb223"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA512_224_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA512_224_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA512_224),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    192,
                    new String[]
                        {
                            "931718bd179349d99882f13c9d16ddba639ae89e6e92ece3a1fd6088fcd0b9821b5cabc804dd1375",
                            "6f21305054548f4ff22df977400b2872ca2ae51548b04d1d23efce063922a173e5cac092d18a959d"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA512_256_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA512_256_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA512_256),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "936ececd2492af2b0635b68ce348d5aa9183e585b7c655169a2b3f20655f30b94fc1c386c8a1a6ae",
                            "fa4e1148e8d35dbd47982d78ae7d1b1eb3d6c4241f2c5b84868c019c8dd494cc7704dcc5fdc414fb"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            SHA512_256_HMAC.getAlgorithm(), new DRBGHMACSelfTest(SHA512_256_HMAC.getAlgorithm(),
                new DRBGTestVector(
                    FipsSHS.createDigest(FipsSHS.Algorithm.SHA512_256),
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "936ececd2492af2b0635b68ce348d5aa9183e585b7c655169a2b3f20655f30b94fc1c386c8a1a6ae",
                            "fa4e1148e8d35dbd47982d78ae7d1b1eb3d6c4241f2c5b84868c019c8dd494cc7704dcc5fdc414fb"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            CTR_Triple_DES_168.getAlgorithm(), new DRBGCTRSelfTest(CTR_Triple_DES_168.getAlgorithm(),
                new DRBGTestVector(
                    FipsTripleDES.ENGINE_PROVIDER.createEngine(),
                    168,
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    112,
                    new String[]
                        {
                            "37b8b6d90405c2e47726c62bf83705bcfadb4e4239abec8dbdbc1ed544d83e7a7971ef0b7366d860",
                            "f9f2cc6db6b4496f0c0b7005d4e22b6f13034e44a559b03437582eafd4991b27927fbb1faa860ebd"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            CTR_AES_128.getAlgorithm(), new DRBGCTRSelfTest(CTR_AES_128.getAlgorithm(),
                new DRBGTestVector(
                    FipsAES.ENGINE_PROVIDER.createEngine(),
                    128,
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    128,
                    new String[]
                        {
                            "8339142c7329b506b61514bdb8fd5ad225d72a564b1025000c33c43281ebbe1cddf0eace9493342e",
                            "b6a51deea6c2b019ab9d03ac730388c3af39d41f45c9263008dcf6e1d63dc8e9ad06624a4b5866ef"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            CTR_AES_192.getAlgorithm(), new DRBGCTRSelfTest(CTR_AES_192.getAlgorithm(),
                new DRBGTestVector(
                    FipsAES.ENGINE_PROVIDER.createEngine(),
                    192,
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    192,
                    new String[]
                        {
                            "f60fc3973fc5815f5515edbd0f7010363ebda8f18b0c2744d17db5fc1a7a9475052bc793baa87a22",
                            "173f3374e076502277f1df52a7cfd694d3cbf03a7e981cf1a9ec36ded6a74aed7e1c4cfa5e149e25"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
        SelfTestExecutor.validate(
            CTR_AES_256.getAlgorithm(), new DRBGCTRSelfTest(CTR_AES_256.getAlgorithm(),
                new DRBGTestVector(
                    FipsAES.ENGINE_PROVIDER.createEngine(),
                    256,
                    new KATEntropyProvider().get(440),
                    true,
                    "2021222324",
                    256,
                    new String[]
                        {
                            "49e16ad6c600a8b588cd286da27ada60419e3f6df2ad7467e80cc53a3dc8119e2364f3d7d2a44097",
                            "92a0b307629eeccb5370ca718da99bdded5f765b6f634916ab88b92441e8c90b91ef203d8448fda0"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
    }

    private abstract static class DRBGSelfTest
        extends VariantInternalKatTest
    {
        DRBGSelfTest(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    private static class DRBGHashSelfTest
        extends DRBGSelfTest
    {
        private final DRBGTestVector tv;

        DRBGHashSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv)
        {
            super(algorithm);
            this.tv = tv;
        }

        @Override
        void evaluate()
            throws Exception
        {
            byte[] nonce = tv.nonce();
            byte[] personalisationString = tv.personalizationString();

            SP80090DRBG d = new HashSP800DRBG(tv.getDigest(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".1 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(0))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".2 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(1))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }
        }
    }

    private static class DRBGHMACSelfTest
        extends DRBGSelfTest
    {
        private final DRBGTestVector tv;

        DRBGHMACSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv)
        {
            super(algorithm);
            this.tv = tv;
        }

        @Override
        void evaluate()
            throws Exception
        {
            byte[] nonce = tv.nonce();
            byte[] personalisationString = tv.personalizationString();

            SP80090DRBG d = new HMacSP800DRBG(new HMac(tv.getDigest()), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".1 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(0))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".2 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(1))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }
        }
    }

    private static class DRBGCTRSelfTest
        extends DRBGSelfTest
    {
        private final DRBGTestVector tv;

        DRBGCTRSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv)
        {
            super(algorithm);
            this.tv = tv;
        }

        @Override
        void evaluate()
            throws Exception
        {
            byte[] nonce = tv.nonce();
            byte[] personalisationString = tv.personalizationString();

            SP80090DRBG d = new CTRSP800DRBG(tv.getCipher(), tv.keySizeInBits(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".1 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(0))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!Arrays.areEqual(expected, output))
            {
                fail("Self test " + algorithm.getName() + ".2 failed, expected " + Strings.fromByteArray(Hex.encode(tv.expectedValue(1))) + " got " + Strings.fromByteArray(Hex.encode(output)));
            }
        }
    }

    private static class DRBGTestVector
    {
        private Digest _digest;
        private BlockCipher _cipher;
        private int _keySizeInBits;
        private EntropySource _eSource;
        private boolean _pr;
        private String _nonce;
        private String _personalisation;
        private int _ss;
        private String[] _ev;
        private List _ai = new ArrayList();

        public DRBGTestVector(Digest digest, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _digest = digest;
            _eSource = eSource;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = null;
        }

        public DRBGTestVector(BlockCipher cipher, int keySizeInBits, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _cipher = cipher;
            _keySizeInBits = keySizeInBits;
            _eSource = eSource;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = null;
        }

        public Digest getDigest()
        {
            return _digest;
        }

        public BlockCipher getCipher()
        {
            return _cipher;
        }

        public int keySizeInBits()
        {
            return _keySizeInBits;
        }

        public DRBGTestVector addAdditionalInput(String input)
        {
            _ai.add(input);

            return this;
        }

        public DRBGTestVector setPersonalizationString(String p)
        {
            _personalisation = p;

            return this;
        }

        public EntropySource entropySource()
        {
            return _eSource;
        }

        public boolean predictionResistance()
        {
            return _pr;
        }

        public byte[] nonce()
        {
            if (_nonce == null)
            {
                return null;
            }

            return Hex.decode(_nonce);
        }

        public byte[] personalizationString()
        {
            if (_personalisation == null)
            {
                return null;
            }

            return Hex.decode(_personalisation);
        }

        public int securityStrength()
        {
            return _ss;
        }

        public byte[] expectedValue(int index)
        {
            return Hex.decode(_ev[index]);
        }

        public byte[] additionalInput(int position)
        {
            int len = _ai.size();
            byte[] rv;
            if (position >= len)
            {
                rv = null;
            }
            else
            {
                rv = Hex.decode((String)(_ai.get(position)));
            }
            return rv;
        }
    }

    private static class KATEntropyProvider
        extends FixedEntropySourceProvider
    {
        KATEntropyProvider()
        {
            super(
                Hex.decode(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536"
                        + "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6"
                        + "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6"), true);
        }
    }
}
