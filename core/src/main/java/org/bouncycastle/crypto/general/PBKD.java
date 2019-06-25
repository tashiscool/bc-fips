package org.bouncycastle.crypto.general;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordBasedDeriverFactory;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.util.Arrays;

/**
 * Source class for implementations of Password-Based Key Derivation Algorithms
 */
public final class PBKD
{
    /**
     * Algorithm ID for PBKDF2 (PKCS#5 scheme 2)
     */
    private static final GeneralAlgorithm ALGORITHM_PBKDF2 = new GeneralAlgorithm("PBKDF2");
    /**
     * Algorithm ID for PBKDF2 (PKCS#5 scheme 1)
     */
    private static final GeneralAlgorithm ALGORITHM_PBKDF1 = new GeneralAlgorithm("PBKDF1");
    /**
     * Algorithm ID for PKCS#12
     */
    private static final GeneralAlgorithm ALGORITHM_PKCS12 = new GeneralAlgorithm("PKCS12");
    /**
     * Algorithm ID for OpenSSL
     */
    private static final GeneralAlgorithm ALGORITHM_OpenSSL = new GeneralAlgorithm("OpenSSL");

    /**
     * PBKDF1 algorithm parameter source - default PRF is SHA-1
     */
    public static final ParametersBuilder PBKDF1 = new ParametersBuilder(ALGORITHM_PBKDF1, FipsSHS.Algorithm.SHA1);

    /**
     * PBKDF2 algorithm parameter source - default PRF is HMAC(SHA-1)
     */
    public static final ParametersBuilder PBKDF2 = new ParametersBuilder(ALGORITHM_PBKDF2, FipsSHS.Algorithm.SHA1_HMAC);

    /**
     * PKCS#12 PBE algorithm parameter source - default PRF is SHA-1
     */
    public static final ParametersBuilder PKCS12 = new ParametersBuilder(ALGORITHM_PKCS12, FipsSHS.Algorithm.SHA1);

    /**
     * OpenSSL PBE algorithm parameter source - PRF is MD5
     */
    public static final OpenSSLParametersBuilder OpenSSL = new OpenSSLParametersBuilder();

    private PBKD()
    {

    }

    /**
     * Initial builder for general PBKD parameters.
     */
    public static final class ParametersBuilder
        extends GeneralParameters
    {
        private final DigestAlgorithm defaultPrf;

        ParametersBuilder(GeneralAlgorithm algorithm, DigestAlgorithm defaultPrf)
        {
            super(algorithm);
            this.defaultPrf = defaultPrf;
        }

        public Parameters using(byte[] password)
        {
            return using(defaultPrf, password);
        }

        public Parameters using(DigestAlgorithm digestAlgorithm, byte[] password)
        {
            return new Parameters((GeneralAlgorithm)getAlgorithm(), digestAlgorithm, null, Arrays.clone(password), 1024, new byte[20]);
        }

        public Parameters using(PasswordConverter converter, char[] password)
        {
            return new Parameters((GeneralAlgorithm)getAlgorithm(), defaultPrf, converter, password);
        }

        public Parameters using(DigestAlgorithm digestAlgorithm, PasswordConverter converter, char[] password)
        {
            return new Parameters((GeneralAlgorithm)getAlgorithm(), digestAlgorithm, converter, converter.convert(password), 1024, new byte[20]);
        }
    }

    /**
     * Initial builder for OpenSSL
     */
    public static final class OpenSSLParametersBuilder
        extends GeneralParameters
    {
        OpenSSLParametersBuilder()
        {
            super(ALGORITHM_OpenSSL);
        }

        public Parameters using(byte[] password)
        {
            return new Parameters((GeneralAlgorithm)getAlgorithm(), SecureHash.Algorithm.MD5, null, Arrays.clone(password), 1024, new byte[20]);
        }

        public Parameters using(PasswordConverter converter, char[] password)
        {
            return new Parameters((GeneralAlgorithm)getAlgorithm(), SecureHash.Algorithm.MD5, converter, converter.convert(password), 1024, new byte[20]);
        }
    }

    /**
     * PBKD parameters.
     */
    public static final class Parameters
        extends GeneralParameters<Algorithm>
    {
        private final DigestAlgorithm digestAlgorithm;
        private final PasswordConverter converter;
        private final byte[] password;

        private final byte[] salt;
        private final int iterationCount;

        private Parameters(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm, PasswordConverter converter, byte[] password, int iterationCount, byte[] salt)
        {
            super(algorithm);
            this.digestAlgorithm = digestAlgorithm;
            this.converter = converter;
            this.password = password;
            this.iterationCount = iterationCount;
            this.salt = salt;
        }

        private Parameters(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm, PasswordConverter converter, char[] password)
        {
            this(algorithm, digestAlgorithm, converter, converter.convert(password), 1024, new byte[20]);
        }

        public Parameters withSalt(byte[] salt)
        {                                                             // need copy of password as zeroize on finalisation
            return new Parameters((GeneralAlgorithm)getAlgorithm(), digestAlgorithm, converter, getPassword(), iterationCount, Arrays.clone(salt));
        }

        public Parameters withIterationCount(int iterationCount)
        {                                                             // need copy of password as zeroize on finalisation
            return new Parameters((GeneralAlgorithm)getAlgorithm(), digestAlgorithm, converter, getPassword(), iterationCount, salt);
        }

        byte[] getPassword()
        {
            return Arrays.clone(password);
        }

        public DigestAlgorithm getPRF()
        {
            return digestAlgorithm;
        }

        public byte[] getSalt()
        {
            return Arrays.clone(salt);
        }

        public int getIterationCount()
        {
            return iterationCount;
        }

        public PasswordConverter getConverter()
        {
            return converter;
        }

        @Override
        protected void finalize()
            throws Throwable
        {
            super.finalize();

            // explicitly zeroize password on deallocation
            Arrays.fill(password, (byte)0);
        }
    }

    private static Map<Algorithm, PasswordBasedDeriverFactory<Parameters>> deriverTable = new HashMap<Algorithm, PasswordBasedDeriverFactory<Parameters>>();

    static
    {
        deriverTable.put(ALGORITHM_PBKDF2, new PBKDF2DeriverFactory());
        deriverTable.put(ALGORITHM_PBKDF1, new PBKDF1DeriverFactory());
        deriverTable.put(ALGORITHM_PKCS12, new PKCS12DeriverFactory());
        deriverTable.put(ALGORITHM_OpenSSL, new OpenSSLDeriverFactory());
    }

    /**
     * Factory for password based key derivation functions.
     */
    public static class DeriverFactory
        extends GuardedPasswordBasedDeriverFactory<Parameters>
    {
        public PasswordBasedDeriver<Parameters> createDeriver(final Parameters parameters)
        {
            return deriverTable.get(parameters.getAlgorithm()).createDeriver(parameters);
        }
    }

    /**
     * Factory for password based key derivation functions that are based on PBKDF1 (PKCS#5 scheme 1).
     */
    private static class PBKDF1DeriverFactory
        extends GuardedPasswordBasedDeriverFactory<Parameters>
    {
        public PasswordBasedDeriver<Parameters> createDeriver(final Parameters parameters)
        {
            final PKCS5S1ParametersGenerator<Parameters> gen = new PKCS5S1ParametersGenerator<Parameters>(parameters, Register.createDigest(parameters.getPRF()));

            gen.init(parameters.getPassword(), parameters.getSalt(), parameters.getIterationCount());

            return new PasswordBasedDeriver<Parameters>()
            {
                public Parameters getParameters()
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return parameters;
                }

                public byte[] deriveKey(KeyType keyType, int keySizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKey(keyType, keySizeInBytes);
                }

                public byte[][] deriveKeyAndIV(KeyType keyType, int keySizeInBytes, int ivSizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKeyAndIV(keyType, keySizeInBytes, ivSizeInBytes);
                }
            };
        }
    }

    /**
     * Factory for password based key derivation functions.
     */
    private static class PBKDF2DeriverFactory
        extends GuardedPasswordBasedDeriverFactory<Parameters>
    {
        public PasswordBasedDeriver<Parameters> createDeriver(final Parameters parameters)
        {
            final PKCS5S2ParametersGenerator<Parameters> gen = new PKCS5S2ParametersGenerator<Parameters>(parameters, Register.createHMac(parameters.getPRF()));

            gen.init(parameters.getPassword(), parameters.getSalt(), parameters.getIterationCount());

            return new PasswordBasedDeriver<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public byte[] deriveKey(KeyType keyType, int keySizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKey(keyType, keySizeInBytes);
                }

                public byte[][] deriveKeyAndIV(KeyType keyType, int keySizeInBytes, int ivSizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKeyAndIV(keyType, keySizeInBytes, ivSizeInBytes);
                }
            };
        }
    }

    /**
     * Factory for password based key derivation functions that are based on PKCS#12.
     */
    private static class PKCS12DeriverFactory
        extends GuardedPasswordBasedDeriverFactory<Parameters>
    {
        public PasswordBasedDeriver<Parameters> createDeriver(final Parameters parameters)
        {
            final PKCS12ParametersGenerator<Parameters> gen = new PKCS12ParametersGenerator<Parameters>(parameters, Register.createDigest(parameters.getPRF()));

            gen.init(parameters.getPassword(), parameters.getSalt(), parameters.getIterationCount());

            return new PasswordBasedDeriver<Parameters>()
            {
                public Parameters getParameters()
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return parameters;
                }

                public byte[] deriveKey(KeyType keyType, int keySizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKey(keyType, keySizeInBytes);
                }

                public byte[][] deriveKeyAndIV(KeyType keyType, int keySizeInBytes, int ivSizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKeyAndIV(keyType, keySizeInBytes, ivSizeInBytes);
                }
            };
        }
    }

    /**
     * Factory for password based key derivation functions that are based on the algorithm used by OpenSSL.
     */
    private static class OpenSSLDeriverFactory
        extends GuardedPasswordBasedDeriverFactory<Parameters>
    {
        public PasswordBasedDeriver<Parameters> createDeriver(final Parameters parameters)
        {
            if (parameters.getPRF() != SecureHash.Algorithm.MD5)
            {
                throw new IllegalArgumentException("OpenSSL PBKDF only defined for MD5");
            }

            final OpenSSLPBEParametersGenerator<Parameters> gen = new OpenSSLPBEParametersGenerator<Parameters>(parameters);

            gen.init(parameters.getPassword(), parameters.getSalt(), parameters.getIterationCount());

            return new PasswordBasedDeriver<Parameters>()
            {
                public Parameters getParameters()
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return parameters;
                }

                public byte[] deriveKey(KeyType keyType, int keySizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKey(keyType, keySizeInBytes);
                }

                public byte[][] deriveKeyAndIV(KeyType keyType, int keySizeInBytes, int ivSizeInBytes)
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return gen.deriveKeyAndIV(keyType, keySizeInBytes, ivSizeInBytes);
                }
            };
        }
    }
}
