package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.fips.FipsTripleDES;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.Wrapper;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;

/**
 * Source class for non-FIPS approved-mode implementations of TripleDES based algorithms.
 */
public final class TripleDES
{
    private TripleDES()
    {

    }

    /**
     * Convenience link back to FipsTripleDES.
     */
    public static final Algorithm ALGORITHM = FipsTripleDES.ALGORITHM;

    /**
     * Triple-DES  CBC-MAC.
     */
    public static final AuthParameters CBC_MAC = new AuthParameters(new GeneralAlgorithm(FipsTripleDES.ALGORITHM.getName(), Mode.CBCMAC));

    /**
     * Triple-DES  CBC-MAC with ISO7816-4 Padding.
     */
    public static final AuthParameters CBC_MACwithISO7816_4 = new AuthParameters(new GeneralAlgorithm(FipsTripleDES.ALGORITHM.getName(), Mode.CBCMAC, Padding.ISO7816_4));

    /**
     * Triple-DES  CFB8-MAC.
     */
    public static final AuthParameters CFB8_MAC = new AuthParameters(new GeneralAlgorithm(FipsTripleDES.ALGORITHM.getName(), Mode.CFB8MAC));

    /**
     * Triple-DES in OpenPGP cipher feedback (CFB) mode.
     */
    public static final Parameters OpenPGPCFB = new Parameters(new GeneralAlgorithm(FipsTripleDES.ALGORITHM.getName(), Mode.OpenPGPCFB));

    /**
     * Triple-DES in EAX mode..
     */
    public static final AuthParameters EAX = new AuthParameters(new GeneralAlgorithm(FipsTripleDES.ALGORITHM.getName(), Mode.EAX));

    /**
     * Triple-DES RFC 3217, PKCS CMS Wrap mode
     */
    public static final Parameters RFC3217_WRAP = new Parameters(new GeneralAlgorithm(FipsTripleDES.ALGORITHM.getName(), Mode.RFC3217_WRAP));

    /**
     * Triple-DES RFC 3211, CMS PBE Wrap mode
     */
    public static final Parameters RFC3211_WRAP = new Parameters(new GeneralAlgorithm(FipsTripleDES.ALGORITHM.getName(), Mode.RFC3211_WRAP));

    /**
     * Parameters for general Triple-DES non-FIPS block cipher modes.
     */
    public static final class Parameters
        extends GeneralParametersWithIV<Parameters>
    {
        private Parameters(GeneralAlgorithm algorithm, byte[] iv)
        {
            super(algorithm, 8, algorithm.checkIv(iv, 8));
        }

        public Parameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        protected Parameters create(GeneralAlgorithm algorithm, byte[] iv)
        {
            return new Parameters(algorithm, iv);
        }
    }

    /**
     * Parameters for Triple-DES non-FIPS AEAD and MAC modes..
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
        public AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null, Utils.getDefaultMacSize(algorithm, 64));  // tag full blocksize or half
        }

        protected AuthParameters create(GeneralAlgorithm algorithm, byte[] iv, int macSizeInBits)
        {
            return new AuthParameters(algorithm, iv, macSizeInBits);
        }
    }

    /**
     * Specific Triple-DES key generator for non-FIPS algorithms.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final FipsTripleDES.KeyGenerator keyGen;

        public KeyGenerator(GeneralParameters parameterSet, int keySizeInBits, SecureRandom random)
        {
            this.algorithm = (GeneralAlgorithm)parameterSet.getAlgorithm();
            this.keyGen = new FipsTripleDES.KeyGenerator(keySizeInBits, random);
        }

        public SymmetricKey doGenerateKey()
        {
            return new SymmetricSecretKey(algorithm, keyGen.generateKey().getKeyBytes());
        }
    }

    /**
     * Factory for basic non-FIPS Triple-DES encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedSymmetricOperatorFactory<Parameters>
    {
        @Override
        protected BufferedBlockCipher createCipher(boolean forEncryption, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            return CipherUtils.createStandardCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), FipsRegister.<BlockCipher>getProvider(FipsTripleDES.ALGORITHM), parameters, random);
        }
    }

    /**
     * Factory for non-FIPS Triple-DES AEAD encryption/decryption operators.
     */
    public static final class AEADOperatorFactory
        extends GuardedAEADOperatorFactory<AuthParameters>
    {
        @Override
        protected AEADBlockCipher createAEADCipher(boolean forEncryption, SymmetricKey key, AuthParameters parameters)
        {
            return CipherUtils.createStandardAEADCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), FipsRegister.<BlockCipher>getProvider(FipsTripleDES.ALGORITHM), parameters);
        }
    }

    /**
     * Factory for producing non-FIPS Triple-DES MAC calculators.
     */
    public static final class MACOperatorFactory
        extends GuardedMACOperatorFactory<AuthParameters>
    {
        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            return CipherUtils.createStandardMac(validateKey(key, parameters.getAlgorithm()), FipsRegister.<BlockCipher>getProvider(FipsTripleDES.ALGORITHM), parameters);
        }

        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return Utils.bitsToBytes(parameters.macLenInBits);
        }
    }

    /**
     * Factory for non-FIPS Triple-DES key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        extends GuardedKeyWrapOperatorFactory<Parameters, SymmetricKey>
    {
        @Override
        protected Wrapper createWrapper(boolean forWrapping, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            return CipherUtils.createStandardWrapper(forWrapping, validateKey(key, parameters.getAlgorithm()), FipsRegister.<BlockCipher>getProvider(FipsTripleDES.ALGORITHM), parameters, random);
        }
    }

    private static void validateKeySize(int keySize)
    {
        if (keySize != 112 && keySize != 168 && keySize != 128 && keySize != 192)
        {
            throw new IllegalKeyException("DESEDE key must be of length 128 or 192 bits");
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm algorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        validateKeySize(vKey.getKeySizeInBits());

        Utils.checkKeyAlgorithm(vKey, FipsTripleDES.ALGORITHM, algorithm);

        return vKey;
    }
}
