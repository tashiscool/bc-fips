package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.crypto.AEADOperatorFactory;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.OutputAEADDecryptor;
import org.bouncycastle.crypto.OutputAEADEncryptor;
import org.bouncycastle.crypto.OutputCipher;
import org.bouncycastle.crypto.OutputDecryptor;
import org.bouncycastle.crypto.OutputEncryptor;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricOperatorFactory;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.fips.FipsAEADOperatorFactory;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsParameters;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsSymmetricOperatorFactory;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.jcajce.PBKDF1Key;
import org.bouncycastle.jcajce.PBKDF2Key;
import org.bouncycastle.jcajce.PBKDFKey;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.Strings;

class BaseCipher
    extends CipherSpi
{
    static class Builder
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private final int blockSize;
        private final Algorithm[] algorithms;
        private final Map<Algorithm, Parameters> baseParametersMap;

        private FipsSymmetricOperatorFactory fipsFactory;
        private SymmetricOperatorFactory generalFactory;
        private FipsAEADOperatorFactory fipsAeadFactory;
        private AEADOperatorFactory generalAeadFactory;
        private Class[] availableSpecs;
        private int keySizeInBits;
        private ParametersCreatorProvider fipsParametersProvider;
        private ParametersCreatorProvider generalParametersProvider;
        private DigestAlgorithm prf = FipsSHS.Algorithm.SHA1;
        private PBEScheme scheme;

        Builder(BouncyCastleFipsProvider fipsProvider, int blockSize, Parameters... parameters)
        {
            this.fipsProvider = fipsProvider;
            this.blockSize = blockSize;
            this.baseParametersMap = new HashMap<Algorithm, Parameters>(parameters.length);
            this.algorithms = new Algorithm[parameters.length];
            for (int i = 0; i != parameters.length; i++)
            {
                this.baseParametersMap.put(parameters[i].getAlgorithm(), parameters[i]);
                this.algorithms[i] = parameters[i].getAlgorithm();
            }
        }

        Builder withFixedKeySize(int keySizeInBits)
        {
            this.keySizeInBits = keySizeInBits;

            return this;
        }

        Builder withFipsOperators(ParametersCreatorProvider fipsParametersProvider, FipsSymmetricOperatorFactory fipsFactory)
        {
            this.fipsParametersProvider = fipsParametersProvider;
            this.fipsFactory = fipsFactory;

            return this;
        }

        Builder withFipsOperators(ParametersCreatorProvider fipsParametersProvider, FipsSymmetricOperatorFactory fipsFactory, FipsAEADOperatorFactory fipsAeadFactory)
        {
            this.fipsParametersProvider = fipsParametersProvider;
            this.fipsFactory = fipsFactory;
            this.fipsAeadFactory = fipsAeadFactory;

            return this;
        }

        Builder withGeneralOperators(ParametersCreatorProvider generalParametersProvider, SymmetricOperatorFactory generalFactory, AEADOperatorFactory generalAeadFactory)
        {
            this.generalParametersProvider = generalParametersProvider;
            this.generalFactory = generalFactory;
            this.generalAeadFactory = generalAeadFactory;

            return this;
        }

        Builder withScheme(PBEScheme scheme)
        {
            this.scheme = scheme;

            return this;
        }

        Builder withPrf(DigestAlgorithm prf)
        {
            this.prf = prf;

            return this;
        }

        Builder withParameters(Class[] availableSpecs)
        {
            this.availableSpecs = availableSpecs;

            return this;
        }

        BaseCipher build()
        {
            boolean isInApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();

            if (!isInApprovedMode)
            {
                return new BaseCipher(fipsProvider, blockSize, keySizeInBits, prf, scheme, fipsFactory, generalFactory, fipsAeadFactory, generalAeadFactory, availableSpecs, fipsParametersProvider, generalParametersProvider, baseParametersMap, algorithms);
            }

            Set<Algorithm> activeSet = Utils.getActiveSet(algorithms);

            // no point!
            if (activeSet.isEmpty())
            {
                return null;
            }

            return new BaseCipher(fipsProvider, blockSize, keySizeInBits, prf, scheme, fipsFactory, generalFactory, fipsAeadFactory, generalAeadFactory, availableSpecs, fipsParametersProvider, generalParametersProvider, baseParametersMap, activeSet.toArray(new Algorithm[activeSet.size()]));
        }
    }

    private final BouncyCastleFipsProvider fipsProvider;
    private final FipsSymmetricOperatorFactory fipsFactory;
    private final SymmetricOperatorFactory generalFactory;
    private final FipsAEADOperatorFactory fipsAeadFactory;
    private final AEADOperatorFactory generalAeadFactory;
    private final int blockSizeInBits;
    private final int keySizeInBits;
    private final DigestAlgorithm prf;
    private final Class[] fipsAvailableSpecs;
    private final Class[] generalAvailableSpecs;
    private final ParametersCreatorProvider<FipsParameters> fipsParametersProvider;
    private final ParametersCreatorProvider<Parameters> generalParametersProvider;
    private final Algorithm[] algorithms;
    private final Map<Algorithm, Parameters> baseParametersMap;
    private final PBEScheme scheme;

    private Set<Algorithm> activeAlgorithmSet = new HashSet<Algorithm>();

    private int                     ivLength = 0;

    private boolean                 padded;

    private PBEParameterSpec        pbeSpec = null;
    private String                  pbeAlgorithm = null;

    private AlgorithmParameters     engineParams = null;
    private String                  modeName = null;

    private int                      opMode;

    private OutputCipher<Parameters> cipher;

    private OutputEncryptor<Parameters>    encryptor;


    private OutputDecryptor<Parameters> decryptor;

    private UpdateOutputStream aadStream;
    private UpdateOutputStream processingStream;
    private ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    private byte[] associatedData = null;

    private BaseCipher(BouncyCastleFipsProvider fipsProvider, int blockSizeInBits, int keySizeInBits, DigestAlgorithm prf, PBEScheme scheme,
                       FipsSymmetricOperatorFactory fipsFactory, SymmetricOperatorFactory generalFactory,
                       FipsAEADOperatorFactory fipsAeadFactory, AEADOperatorFactory generalAeadFactory,
                       Class[] availableSpecs,
                       ParametersCreatorProvider fipsParametersCreatorProvider,
                       ParametersCreatorProvider generalParametersCreatorProvider,
                       Map<Algorithm, Parameters> baseParametersMap,
                       Algorithm... algorithms)
    {
        this.fipsProvider = fipsProvider;
        this.keySizeInBits = keySizeInBits;
        this.prf = prf;
        this.scheme = scheme;
        this.fipsFactory = fipsFactory;
        this.generalFactory = generalFactory;
        this.fipsAeadFactory = fipsAeadFactory;
        this.generalAeadFactory = generalAeadFactory;
        this.blockSizeInBits = blockSizeInBits;
        this.fipsAvailableSpecs = availableSpecs;
        this.generalAvailableSpecs = availableSpecs;
        this.fipsParametersProvider = fipsParametersCreatorProvider;
        this.generalParametersProvider = generalParametersCreatorProvider;
        this.baseParametersMap = baseParametersMap;
        this.algorithms = algorithms;
        activeAlgorithmSet.addAll(Arrays.asList((Algorithm[])algorithms));
    }

    protected int engineGetBlockSize()
    {
        return (blockSizeInBits + 7) / 8;
    }

    protected byte[] engineGetIV()
    {
        Parameters params = cipher.getParameters();

        if (params instanceof org.bouncycastle.crypto.ParametersWithIV)
        {
            return ((org.bouncycastle.crypto.ParametersWithIV)params).getIV();
        }

        return null;
    }

    protected int engineGetKeySize(
        Key     key)
    {
        return key.getEncoded().length * 8;
    }

    protected int engineGetOutputSize(
        int     inputLen)
    {
        return cipher.getMaxOutputSize(inputLen);
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null && cipher != null)
        {
            Parameters params = cipher.getParameters();
            String  name = Utils.getBaseName(params.getAlgorithm());

            if (params instanceof AuthenticationParametersWithIV)
            {
                try
                {
                    AuthenticationParametersWithIV authParams = (AuthenticationParametersWithIV)params;

                    engineParams = AlgorithmParameters.getInstance(name, fipsProvider);
                    engineParams.init(new GCMParameters(authParams.getIV(), authParams.getMACSizeInBits() / 8).getEncoded());
                }
                catch (Exception e)
                {
                    throw new IllegalStateException(e.toString(), e);
                }
            }
            else if (params instanceof org.bouncycastle.crypto.ParametersWithIV)
            {
                ParametersWithIV ivParams = (ParametersWithIV)params;

                if (ivParams.getIV() != null)
                {
                    try
                    {
                        engineParams = AlgorithmParameters.getInstance(name, fipsProvider);

                        engineParams.init(new DEROctetString(ivParams.getIV()).getEncoded());
                    }
                    catch (Exception e)
                    {
                        throw new IllegalStateException(e.toString(), e);
                    }
                }
            }

            if (pbeSpec != null)
            {
                try
                {
                    engineParams = AlgorithmParameters.getInstance(pbeAlgorithm, fipsProvider);
                    engineParams.init(pbeSpec);
                }
                catch (Exception e)
                {
                    return null;
                }
            }
        }

        return engineParams;
    }

    protected void engineSetMode(
        String  mode)
        throws NoSuchAlgorithmException
    {
        modeName = Strings.toUpperCase(mode);

        String modeMatch2;
        String modeMatch1;

        if (modeName.equals("CTS"))
        {
            modeName = "CBC/CS3";
        }

        if (modeName.equals("SIC"))
        {
            modeMatch2 = "/CTR";
            modeMatch1 = "/CTR/";
        }
        else if (modeName.equals("CFB") || modeName.equals("OFB"))
        {
            modeMatch2 = "/" + modeName + Integer.toString(blockSizeInBits);
            modeMatch1 = "/" + modeName + Integer.toString(blockSizeInBits) + "/";
        }
        else
        {
            modeMatch2 = "/" + modeName;
            modeMatch1 = "/" + modeName + "/";
        }

        Set<Algorithm> currentAlgs = new HashSet<Algorithm>(activeAlgorithmSet);

        activeAlgorithmSet.clear();

        for (Algorithm alg : currentAlgs)
        {
            if (alg.getName().endsWith(modeMatch2) || alg.getName().contains(modeMatch1))
            {
                 activeAlgorithmSet.add(alg);
            }
        }

        if (activeAlgorithmSet.isEmpty())
        {
            throw new NoSuchAlgorithmException(modeName + " not found");
        }
    }

    protected void engineSetPadding(
        String  padding)
    throws NoSuchPaddingException
    {
        String  paddingName = Strings.toUpperCase(padding);

        Set<Algorithm> currentAlgs = new HashSet<Algorithm>(activeAlgorithmSet);

        activeAlgorithmSet.clear();

        if (paddingName.equals("NOPADDING"))
        {
            padded = false;
            for (Algorithm alg : currentAlgs)
            {
                // one or none
                if (alg.getName().indexOf('/') == alg.getName().lastIndexOf('/'))
                {
                     activeAlgorithmSet.add(alg);
                }
            }

            if (activeAlgorithmSet.isEmpty() && currentAlgs.size() == 1)
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("CS3"))
                    {
                        activeAlgorithmSet.add(alg);
                    }
                }
            }
        }
        else
        {
            padded = true;

            if (paddingName.equals("PKCS5PADDING") || paddingName.equals("PKCS7PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("PKCS7"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("ISO10126PADDING") || paddingName.equals("ISO10126-2PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("ISO10126-2"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("X9.23PADDING") || paddingName.equals("X923PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("X9.23"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("ISO7816-4PADDING") || paddingName.equals("ISO9797-1PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("ISO7816-4"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("TBCPADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("TBC"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("CTSPADDING") || paddingName.equals("CS3PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("CS3"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("CS1PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("CS1"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("CS2PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("CS2"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else
            {
                throw new NoSuchPaddingException("Padding " + padding + " unknown");
            }
        }

        if (activeAlgorithmSet.isEmpty())
        {
            throw new NoSuchPaddingException(paddingName + " not found");
        }
    }

    protected void engineInit(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        this.opMode = opmode;



        this.pbeAlgorithm = null;
        this.engineParams = null;
//        this.aeadParams = null;

        //
        // basic key check
        //
        if (!(key instanceof SecretKey))
        {
            throw new InvalidKeyException("Key for algorithm " + key.getAlgorithm() + " not suitable for symmetric enryption.");
        }

        if (random == null)
        {
            random = fipsProvider.getDefaultSecureRandom();
        }

        Algorithm alg = getAlgorithm();
        ParametersCreator parametersCreator;
        SymmetricOperatorFactory<Parameters> operatorFactory;
        AEADOperatorFactory<Parameters> aeadOperatorFactory;

        if (alg instanceof FipsAlgorithm)
        {
            parametersCreator = fipsParametersProvider.get((FipsParameters)baseParametersMap.get(alg));
            operatorFactory = fipsFactory;
            aeadOperatorFactory = fipsAeadFactory;
        }
        else
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new FipsUnapprovedOperationError("Cipher cannot be used in approved mode");
            }
            parametersCreator = generalParametersProvider.get(baseParametersMap.get(alg));
            operatorFactory = generalFactory;
            aeadOperatorFactory = generalAeadFactory;
        }

        boolean forEncryption;

        switch (opmode)
        {
        case Cipher.ENCRYPT_MODE:
        case Cipher.WRAP_MODE:
            forEncryption = true;
            break;
        case Cipher.UNWRAP_MODE:
        case Cipher.DECRYPT_MODE:
            forEncryption = false;
            break;
        default:
            throw new InvalidParameterException("unknown opmode " + opmode + " passed");
        }

        Parameters parameters;


        if ((key instanceof PBEKey && !(key instanceof PBKDFPBEKey)) || scheme != null || params instanceof PBEParameterSpec)
        {
            PBEParameterSpec spec;

            if (params instanceof PBEParameterSpec)
            {
                this.pbeSpec = spec = (PBEParameterSpec)params;
            }
            else if (key instanceof PBEKey)
            {
                PBEKey pbeKey = (PBEKey)key;

                this.pbeSpec = spec = new PBEParameterSpec(pbeKey.getSalt(), pbeKey.getIterationCount());
            }
            else
            {
                if (!(key instanceof PBEKey))
                {
                    throw new InvalidKeyException("Algorithm requires a PBE key");
                }

                throw new InvalidAlgorithmParameterException("No algorithm parameters provided when required");
            }

            SecretKey pbeKey;

            try
            {
                pbeKey = (SecretKey)key;
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("Algorithm requires a PBE key");
            }

            if (keySizeInBits == 0)
            {
                throw new InvalidAlgorithmParameterException("Invalid algorithm parameter: cannot use PBE with variable key size");
            }

            if (key instanceof PBKDF2Key || scheme == PBEScheme.PBKDF2)
            {
                pbeAlgorithm = "PBKDF2";
                key = new SecretKeySpec(ProvPBEPBKDF2.getSecretKey(pbeKey, spec, PasswordBasedDeriver.KeyType.CIPHER, keySizeInBits), alg.getName());

                try
                {
                    if (alg.requiresAlgorithmParameters())
                    {
                        if (params == null)
                        {
                            throw new InvalidKeyException("No algorithm parameters provided when required");
                        }

                        parameters = parametersCreator.createParameters(forEncryption, params, random);
                    }
                    else
                    {
                        parameters = parametersCreator.createParameters(forEncryption, null, random);
                    }
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidAlgorithmParameterException("Invalid algorithm parameter: " + e.getMessage(), e);
                }
            }
            else if (key instanceof PBKDF1Key || scheme == PBEScheme.PBKDF1)
            {
                pbeAlgorithm = "PBKDF1";
                if (alg.requiresAlgorithmParameters())
                {
                    byte[][] kAndIv = ProvPBEPBKDF1.getSecretKeyAndIV(pbeKey, spec, prf, PasswordBasedDeriver.KeyType.CIPHER, keySizeInBits, blockSizeInBits);

                    key = new SecretKeySpec(kAndIv[0], alg.getName());

                    try
                    {
                        parameters = parametersCreator.createParameters(forEncryption, (params != null && !(params instanceof PBEParameterSpec)) ? params : new IvParameterSpec(kAndIv[1]), random);
                    }
                    catch (IllegalArgumentException e)
                    {
                        throw new InvalidAlgorithmParameterException("Invalid algorithm parameter: " + e.getMessage(), e);
                    }
                }
                else
                {
                    key = new SecretKeySpec(ProvPBEPBKDF1.getSecretKey(pbeKey, spec, prf, PasswordBasedDeriver.KeyType.CIPHER, keySizeInBits), alg.getName());

                    try
                    {
                        parameters = parametersCreator.createParameters(forEncryption, null, random);
                    }
                    catch (IllegalArgumentException e)
                    {
                        throw new InvalidAlgorithmParameterException("Invalid algorithm parameter: " + e.getMessage(), e);
                    }
                }
            }
            else if (key instanceof PKCS12Key || scheme == PBEScheme.PKCS12)
            {
                pbeAlgorithm = "PBKDF-PKCS12";
                if (alg.requiresAlgorithmParameters())
                {
                    byte[][] kAndIv = ProvPKCS12.getSecretKeyAndIV(pbeKey, prf, spec, PasswordBasedDeriver.KeyType.CIPHER, keySizeInBits, blockSizeInBits);

                    key = new SecretKeySpec(kAndIv[0], alg.getName());

                    try
                    {
                        parameters = parametersCreator.createParameters(forEncryption, (params != null && !(params instanceof PBEParameterSpec)) ? params : new IvParameterSpec(kAndIv[1]), random);
                    }
                    catch (IllegalArgumentException e)
                    {
                        throw new InvalidAlgorithmParameterException("Invalid algorithm parameter: " + e.getMessage(), e);
                    }
                }
                else
                {
                    key = new SecretKeySpec(ProvPKCS12.getSecretKey(pbeKey, spec, PasswordBasedDeriver.KeyType.CIPHER, keySizeInBits), alg.getName());

                    try
                    {
                        parameters = parametersCreator.createParameters(forEncryption, null, random);
                    }
                    catch (IllegalArgumentException e)
                    {
                        throw new InvalidAlgorithmParameterException("Invalid algorithm parameter: " + e.getMessage(), e);
                    }
                }
            }
            else
            {
                throw new InvalidKeyException("Unable to use passed in key for PBE");
            }
        }
        else
        {
            if (key instanceof PBKDFKey)
            {
                throw new InvalidKeyException("PBE key requires a PBEParameterSpec");
            }

            if (!forEncryption && alg.requiresAlgorithmParameters() && params == null)
            {
                throw new InvalidAlgorithmParameterException("No algorithm parameters provided when required");
            }

            try
            {
                parameters = parametersCreator.createParameters(forEncryption, params, random);
            }
            catch (IllegalArgumentException e)
            {
                throw new InvalidAlgorithmParameterException("Invalid algorithm parameter: " + e.getMessage(), e);
            }
        }

        try
        {
            SymmetricKey symmetricKey = Utils.convertKey(alg, key);

            if (keySizeInBits != 0 && Utils.keyNotLength(symmetricKey, keySizeInBits))  // restricted key size
            {
                throw new InvalidKeyException("Cipher requires key of size " + keySizeInBits + " bits");
            }

            if (isAEADMode(alg))
            {
                if (forEncryption)
                {
                    cipher = encryptor = Utils.addRandomIfNeeded(aeadOperatorFactory.createOutputAEADEncryptor(symmetricKey, parameters), random);
                    processingStream = encryptor.getEncryptingStream(resultStream);
                    aadStream = ((OutputAEADEncryptor)encryptor).getAADStream();
                }
                else
                {
                    cipher = decryptor = Utils.addRandomIfNeeded(aeadOperatorFactory.createOutputAEADDecryptor(symmetricKey, parameters), random);
                    processingStream = decryptor.getDecryptingStream(resultStream);
                    aadStream = ((OutputAEADDecryptor)decryptor).getAADStream();
                }

                if (params instanceof AEADParameterSpec)
                {
                    associatedData = ((AEADParameterSpec)params).getAssociatedData();
                    if (associatedData != null)
                    {
                        aadStream.update(associatedData);
                    }
                }
            }
            else
            {
                if (forEncryption)
                {
                    cipher = encryptor = Utils.addRandomIfNeeded(operatorFactory.createOutputEncryptor(symmetricKey, parameters), random);
                    processingStream = encryptor.getEncryptingStream(resultStream);
                    aadStream = null;
                }
                else
                {
                    cipher = decryptor = Utils.addRandomIfNeeded(operatorFactory.createOutputDecryptor(symmetricKey, parameters), random);
                    processingStream = decryptor.getDecryptingStream(resultStream);
                    aadStream = null;
                }
            }
        }
        catch (InvalidParameterException e)
        {
            throw e;
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (IllegalKeyException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
        catch (Exception e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    private Algorithm getAlgorithm()
    {
        Algorithm alg;
        if (activeAlgorithmSet.size() == 1)
        {
            alg = activeAlgorithmSet.iterator().next();
        }
        else
        {
            alg = algorithms[0];
        }
        return alg;
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec  paramSpec = null;

        if (params != null)
        {
            Class[] availableSpecs = (getAlgorithm() instanceof FipsAlgorithm) ? fipsAvailableSpecs : generalAvailableSpecs;

            for (int i = 0; i != availableSpecs.length; i++)
            {
                if (availableSpecs[i] == null)
                {
                    continue;
                }

                try
                {
                    paramSpec = params.getParameterSpec(availableSpecs[i]);
                    break;
                }
                catch (Exception e)
                {
                    // try again if possible
                }
            }

            if (paramSpec == null)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }

        engineInit(opmode, key, paramSpec, random);

        engineParams = params;
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        SecureRandom        random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    protected void engineUpdateAAD(byte[] input, int offset, int length)
    {
        aadStream.update(input, offset, length);
    }

    protected void engineUpdateAAD(ByteBuffer bytebuffer)
    {
        int offset = bytebuffer.arrayOffset() + bytebuffer.position();
        int length = bytebuffer.limit() - bytebuffer.position();

        aadStream.update(bytebuffer.array(), offset, length);
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
    {
        processingStream.update(input, inputOffset, inputLen);

        if (resultStream.size() > 0)
        {
            byte[] result = resultStream.toByteArray();

            resultStream.reset();

            return result;
        }

        return null;
    }

    protected int engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws ShortBufferException
    {
        if (outputOffset + cipher.getUpdateOutputSize(inputLen) > output.length)
        {
            throw new ShortBufferException("Output buffer too short for input.");
        }

        byte[] result = engineUpdate(input, inputOffset, inputLen);

        if (result != null)
        {
            System.arraycopy(result, 0, output, outputOffset, result.length);

            return result.length;
        }

        return 0;
    }

    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        try
        {
            if (input != null && inputLen != 0)
            {
                processingStream.update(input, inputOffset, inputLen);
            }

            processingStream.close();
        }
        catch (IOException e)
        {
            if (cipher.getParameters() instanceof AuthenticationParametersWithIV)
            {
                ClassUtil.throwBadTagException(e.getMessage());
            }
            throw new BadPaddingException(e.getMessage());
        }

        byte[] result = resultStream.toByteArray();

        Utils.clearAndResetByteArrayOutputStream(resultStream);

        if (associatedData != null)
        {
            aadStream.update(associatedData);
        }

        return result;
    }

    protected int engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
        if (outputOffset + engineGetOutputSize(inputLen) > output.length)
        {
            throw new ShortBufferException("Output buffer too short for input.");
        }

        byte[] result = engineDoFinal(input, inputOffset, inputLen);

        System.arraycopy(result, 0, output, outputOffset, result.length);

        Arrays.fill(result, (byte)0);

        return result.length;
    }

    protected byte[] engineWrap(
        Key     key)
    throws IllegalBlockSizeException, InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }

        try
        {
            return engineDoFinal(encoded, 0, encoded.length);
        }
        catch (BadPaddingException e)
        {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    protected Key engineUnwrap(
        byte[]  wrappedKey,
        String  wrappedKeyAlgorithm,
        int     wrappedKeyType)
    throws InvalidKeyException, NoSuchAlgorithmException
    {
        byte[] encoded;
        try
        {
                encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        }
        catch (BadPaddingException e)
        {
            throw new InvalidKeyException(e.getMessage());
        }
        catch (IllegalBlockSizeException e)
        {
            throw new InvalidKeyException(e.getMessage());
        }

        return BaseWrapCipher.rebuildKey(wrappedKeyAlgorithm, wrappedKeyType, encoded, fipsProvider);
    }

    private static boolean isAEADMode(Algorithm algorithm)
    {
        String name = algorithm.getName();

        return name.contains("/CCM") || name.contains("/EAX") || name.contains("/GCM") || name.contains("/OCB");
    }
}
