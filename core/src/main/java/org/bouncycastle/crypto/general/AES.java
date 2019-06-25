package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.Wrapper;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;

/**
 * Source class for non-FIPS approved-mode implementations of AES based algorithms.
 */
public final class AES
{
    private AES()
    {

    }

    /**
     * Convenience link back to FipsAES.
     */
    public static final Algorithm ALGORITHM = FipsAES.ALGORITHM;

    /**
     * AES in OpenPGP cipher feedback (CFB) mode.
     */
    public static final Parameters OpenPGPCFB = new Parameters(new GeneralAlgorithm(FipsAES.ALGORITHM.getName(), Mode.OpenPGPCFB));

    /**
     * AES in offset code book (OCB) mode.
     */
    public static final AuthParameters OCB = new AuthParameters(new GeneralAlgorithm(FipsAES.ALGORITHM.getName(), Mode.OCB));

    /**
     * AES in EAX mode.
     */
    public static final AuthParameters EAX = new AuthParameters(new GeneralAlgorithm(FipsAES.ALGORITHM.getName(), Mode.EAX));

    /**
     * AES RFC 3211 key wrapper.
     */
    public static final WrapParameters RFC3211_WRAP = new WrapParameters(new GeneralAlgorithm(FipsAES.ALGORITHM.getName(), Mode.RFC3211_WRAP));

    /**
     * Parameters for general AES non-FIPS block cipher modes.
     */
    public static final class Parameters
        extends GeneralParametersWithIV<Parameters>
    {
        Parameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        private Parameters(GeneralAlgorithm algorithm, byte[] iv)
        {
            super(algorithm, 16, iv);

            ((Mode)algorithm.basicVariation()).checkIv(iv, 16);
        }

        @Override
        Parameters create(GeneralAlgorithm algorithm, byte[] iv)
        {
            return new Parameters(algorithm, iv);
        }
    }

    /**
     * Parameters for AES non-FIPS AEAD and MAC modes..
     */
    public static final class AuthParameters
        extends GeneralAuthParameters<AuthParameters>
    {
        private AuthParameters(GeneralAlgorithm algorithm, byte[] iv, int tagLenInBits)
        {
            super(algorithm, 16, iv, tagLenInBits);
        }

        /**
         * Base constructor - the algorithm, null IV.
         * In this case the tag length defaults to the 128 for GCM or CMAC, 64 bits otherwise.
         *
         * @param algorithm algorithm mode.
         */
        AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null, Utils.getDefaultMacSize(algorithm, 128));  // tag full blocksize or half
        }

        protected AuthParameters create(GeneralAlgorithm algorithm, byte[] iv, int macSizeInBits)
        {
            return new AuthParameters(algorithm, iv, macSizeInBits);
        }
    }

    /**
     * Parameters for general AES non-FIPS key wrapping.
     */
    public static final class WrapParameters
        extends GeneralParametersWithIV<WrapParameters>
    {
        WrapParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        private WrapParameters(GeneralAlgorithm algorithm, byte[] iv)
        {
            super(algorithm, 16, iv);

            ((Mode)algorithm.basicVariation()).checkIv(iv, 16);
        }

        @Override
        WrapParameters create(GeneralAlgorithm algorithm, byte[] iv)
        {
            return new WrapParameters(algorithm, iv);
        }
    }

    /**
     * Specific AES key generator for non-FIPS algorithms.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final FipsAES.KeyGenerator keyGen;

        public KeyGenerator(GeneralParameters parameterSet, int keySizeInBits, SecureRandom random)
        {
            this.algorithm = (GeneralAlgorithm)parameterSet.getAlgorithm();
            this.keyGen = new FipsAES.KeyGenerator(keySizeInBits, random);
        }

        public SymmetricKey doGenerateKey()
        {
            return new SymmetricSecretKey(algorithm, keyGen.generateKey().getKeyBytes());
        }
    }

    /**
     * Factory for basic non-FIPS AES encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedSymmetricOperatorFactory<Parameters>
    {
        @Override
        protected BufferedBlockCipher createCipher(boolean forEncryption, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            return CipherUtils.createStandardCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), FipsRegister.<BlockCipher>getProvider(FipsAES.ALGORITHM), parameters, random);
        }
    }

    /**
     * Factory for non-FIPS AES AEAD encryption/decryption operators.
     */
    public static final class AEADOperatorFactory
        extends GuardedAEADOperatorFactory<AuthParameters>
    {
        @Override
        protected AEADBlockCipher createAEADCipher(boolean forEncryption, SymmetricKey key, AuthParameters parameters)
        {
            return CipherUtils.createStandardAEADCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), FipsRegister.<BlockCipher>getProvider(FipsAES.ALGORITHM), parameters);
        }
    }

    /**
     * Factory for non-FIPS AES key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        extends GuardedKeyWrapOperatorFactory<WrapParameters, SymmetricKey>
    {
        protected Wrapper createWrapper(boolean forWrapping, SymmetricKey key, WrapParameters parameters, SecureRandom random)
        {
            return CipherUtils.createStandardWrapper(forWrapping, validateKey(key, parameters.getAlgorithm()), FipsRegister.<BlockCipher>getProvider(FipsAES.ALGORITHM), parameters, random);
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm algorithm)
    {
        ValidatedSymmetricKey sKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = sKey.getKeySizeInBits();
        if (keyLength != 128 && keyLength != 192 && keyLength != 256)
        {
            throw new IllegalKeyException("AES key must be of length 128, 192, or 256");
        }

        Utils.checkKeyAlgorithm(sKey, FipsAES.ALGORITHM, algorithm);

        return sKey;
    }
}
