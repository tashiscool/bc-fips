package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * The BC FIPS provider.
 * <p>
 *     If no SecureRandom has been specified using CryptoServicesRegistrar.setSecureRandom() the provider class will generate a
 *     FIPS compliant DRBG based on SHA-512. It is also possible to configure the DRBG by passing a string as a constructor
 *     argument to the provider via code, or the java.security configuration file.
 * </p>
 * <p>
 *     At the moment the configuration string is limited to setting the DRBG.The configuration string must always start
 *     with "C:" and finish with "ENABLE{ALL};". The command for setting the actual DRBG type is DEFRND so a configuration
 *     string requesting the use of a SHA1 DRBG would look like:
 *     <pre>
 *         C:DEFRND[SHA1];ENABLE{All};
 *     </pre>
 *     Possible values for the DRBG type are "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512(224)", "SHA512(256)",
 *     "HMACrovRandSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA512(224)", "HMACSHA512(256)", "CTRAES128",
 *     "CTRAES192", CTRAES256", and "CTRDESEDE".
 * </p>
 * <p>
 *     The default DRBG is configured to be prediction resistant. In situations where the amount of entropy is constrained
 *     the default DRBG can be configured to use an entropy pool based on a SHA-512 SP 800-90A DRBG. To configure this use:
 *     <pre>
 *         C:HYBRID;ENABLE{All};
 *     </pre>
 *     or include the string "HYBRID;" in the previous command string setting the DRBG. After initial seeding the entropy pool will
 *     start a reseeding thread which it will begin polling once 20 samples have been taken since the last seeding and will do a reseed
 *     as soon as new entropy bytes are returned.
 * </p>
 * <p>
 *     <b>Note</b>: if the provider is created by an "approved mode" thread, only FIPS approved algorithms will be available from it.
 * </p>
 *
 */
public final class BouncyCastleFipsProvider
    extends Provider
{
    private static final String info = "BouncyCastle Security Provider (FIPS edition) v1.0.1";

    public static final String PROVIDER_NAME = "BCFIPS";

    private static final Map<String, FipsDRBG.Base> drbgTable = new HashMap<String, FipsDRBG.Base>();
    private static final Map<String, Integer> drbgStrengthTable = new HashMap<String, Integer>();

    static
    {
        drbgTable.put("SHA1", FipsDRBG.SHA1);
        drbgTable.put("SHA224", FipsDRBG.SHA224);
        drbgTable.put("SHA256", FipsDRBG.SHA256);
        drbgTable.put("SHA384", FipsDRBG.SHA384);
        drbgTable.put("SHA512", FipsDRBG.SHA512);
        drbgTable.put("SHA512(224)", FipsDRBG.SHA512_224);
        drbgTable.put("SHA512(256)", FipsDRBG.SHA512_256);

        drbgTable.put("HMACSHA1", FipsDRBG.SHA1_HMAC);
        drbgTable.put("HMACSHA224", FipsDRBG.SHA224_HMAC);
        drbgTable.put("HMACSHA256", FipsDRBG.SHA256_HMAC);
        drbgTable.put("HMACSHA384", FipsDRBG.SHA384_HMAC);
        drbgTable.put("HMACSHA512", FipsDRBG.SHA512_HMAC);
        drbgTable.put("HMACSHA512(224)", FipsDRBG.SHA512_224_HMAC);
        drbgTable.put("HMACSHA512(256)", FipsDRBG.SHA512_256_HMAC);

        drbgTable.put("CTRAES128", FipsDRBG.CTR_AES_128);
        drbgTable.put("CTRAES192", FipsDRBG.CTR_AES_192);
        drbgTable.put("CTRAES256", FipsDRBG.CTR_AES_256);
        drbgTable.put("CTRDESEDE", FipsDRBG.CTR_Triple_DES_168);

        drbgStrengthTable.put("SHA1", 128);
        drbgStrengthTable.put("SHA224", 192);
        drbgStrengthTable.put("SHA256", 256);
        drbgStrengthTable.put("SHA384", 256);
        drbgStrengthTable.put("SHA512", 256);
        drbgStrengthTable.put("SHA512(224)", 192);
        drbgStrengthTable.put("SHA512(256)", 256);

        drbgStrengthTable.put("HMACSHA1", 128);
        drbgStrengthTable.put("HMACSHA224", 192);
        drbgStrengthTable.put("HMACSHA256", 256);
        drbgStrengthTable.put("HMACSHA384", 256);
        drbgStrengthTable.put("HMACSHA512", 256);
        drbgStrengthTable.put("HMACSHA512(224)", 192);
        drbgStrengthTable.put("HMACSHA512(256)", 256);

        drbgStrengthTable.put("CTRAES128", 128);
        drbgStrengthTable.put("CTRAES192", 192);
        drbgStrengthTable.put("CTRAES256", 256);
        drbgStrengthTable.put("CTRDESEDE", 112);
    }

    private volatile SecureRandom entropySource;

    private FipsDRBG.Base providerDefaultRandomBuilder = FipsDRBG.SHA512;
    private int providerDefaultSecurityStrength = 256;

    private boolean hybridSource = false;
    private SecureRandom providerDefaultRandom;
    private int providerDefaultRandomSecurityStrength = providerDefaultSecurityStrength;

    private Map<String, BcService> serviceMap = new HashMap<String, BcService>();
    private Map<String, EngineCreator> creatorMap = new HashMap<String, EngineCreator>();

    private final Map<ASN1ObjectIdentifier, AsymmetricKeyInfoConverter> keyInfoConverters = new HashMap<ASN1ObjectIdentifier, AsymmetricKeyInfoConverter>();

    /**
     * Base constructor - build a provider with the default configuration.
     */
    public BouncyCastleFipsProvider()
    {
        this(null);
    }

    /**
     * Constructor accepting a configuration string.
     *
     * @param config the config string.
     */
    public BouncyCastleFipsProvider(String config)
    {
        this(config, null);
    }

    /**
     * Constructor accepting a config string and a user defined source of entropy to be used for the providers locally
     * configured DRBG.
     *
     * @param config        the config string.
     * @param entropySource a SecureRandom which can act as an entropy source.
     */
    public BouncyCastleFipsProvider(String config, SecureRandom entropySource)
    {
        super(PROVIDER_NAME, 1.01, info);

        // TODO: add support for file parsing, selective disable.

        if (config != null)
        {
            if (config.startsWith("C:") || config.startsWith("c:"))
            {
                processConfigString(Strings.toUpperCase(config));
            }
            else
            {
                throw new IllegalArgumentException("Unrecognized config string passed to " + PROVIDER_NAME + " provider.");
            }
        }

        this.entropySource = entropySource;

        new ProvSHS.SHA1().configure(this);
        new ProvSHS.SHA224().configure(this);
        new ProvSHS.SHA256().configure(this);
        new ProvSHS.SHA384().configure(this);
        new ProvSHS.SHA512().configure(this);
        new ProvSHS.SHA3_224().configure(this);
        new ProvSHS.SHA3_256().configure(this);
        new ProvSHS.SHA3_384().configure(this);
        new ProvSHS.SHA3_512().configure(this);
        new ProvSecureHash.MD5().configure(this);  // TLS exception

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvSecureHash.GOST3411().configure(this);

            new ProvSecureHash.RIPEMD128().configure(this);
            new ProvSecureHash.RIPEMD160().configure(this);
            new ProvSecureHash.RIPEMD256().configure(this);
            new ProvSecureHash.RIPEMD320().configure(this);
            new ProvSecureHash.Tiger().configure(this);
            new ProvSecureHash.Whirlpool().configure(this);
        }

        new ProvDH().configure(this);
        new ProvDSA().configure(this);
        new ProvEC().configure(this);

        new ProvRSA().configure(this);

        new ProvPBEPBKDF2().configure(this);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvPBEPBKDF1().configure(this);
            new ProvOpenSSLPBKDF().configure(this);
            new ProvPKCS12().configure(this);
        }

        new ProvAES().configure(this);
        new ProvDESede().configure(this);

        new ProvX509().configure(this);
        new ProvBCFKS().configure(this);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvDSTU4145().configure(this);
            new ProvElgamal().configure(this);
            new ProvGOST3410().configure(this);
            new ProvECGOST3410().configure(this);


            new ProvBlowfish().configure(this);
            new ProvCAST5().configure(this);
            new ProvRC2().configure(this);
            new ProvGOST28147().configure(this);
            new ProvSEED().configure(this);
            new ProvCamellia().configure(this);
            new ProvDES().configure(this);
            new ProvIDEA().configure(this);
            new ProvSerpent().configure(this);
            new ProvSHACAL2().configure(this);
            new ProvTwofish().configure(this);
            new ProvARC4().configure(this);
            new ProvSipHash().configure(this);
        }

        if (!Properties.isOverrideSet("org.bouncycastle.jsse.disable_kdf"))
        {
            AccessController.doPrivileged(new PrivilegedAction<Object>()
            {
                public Object run()
                {
                    if (classExists("sun.security.internal.spec.TlsKeyMaterialParameterSpec")
                        && classExists("sun.security.internal.spec.TlsKeyMaterialSpec")
                        && classExists("sun.security.internal.spec.TlsMasterSecretParameterSpec")
                        && classExists("sun.security.internal.spec.TlsPrfParameterSpec")
                        && classExists("sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec"))
                    {
                        new ProvSunTLSKDF().configure(BouncyCastleFipsProvider.this);
                    }
                    return null;
                }
            });
        }

        if (!Properties.isOverrideSet("org.bouncycastle.pkix.disable_certpath"))
        {
            new ProvPKIX().configure(this);
        }

        if (Properties.isOverrideSet("org.bouncycastle.jca.enable_jks"))
        {
            new ProvJKS().configure(this);
        }

        new ProvRandom().configure(this);
    }

    private void processConfigString(String config)
    {
        String[] commands = config.substring(2).split(";");
        boolean enableAllFound = false;

        for (String command : commands)
        {
            if (command.startsWith("DEFRND"))
            {
                String rnd = extractString('[', ']', command);

                providerDefaultRandomBuilder = drbgTable.get(rnd);
                if (drbgStrengthTable.containsKey(rnd))
                {
                    providerDefaultSecurityStrength = drbgStrengthTable.get(rnd);
                }
                if (providerDefaultRandomBuilder == null)
                {
                    throw new IllegalArgumentException("Unknown DEFRND - " + rnd + " - found in config string.");
                }
            }
            else if (command.startsWith("HYBRID"))
            {
                hybridSource = true;
            }
            else if (command.startsWith("ENABLE"))
            {
                if ("ENABLE{ALL}".equals(command))
                {
                    enableAllFound = true;
                }
            }
        }

        if (!enableAllFound)
        {
            throw new IllegalArgumentException("No ENABLE command found in config string.");
        }
    }

    private String extractString(char startC, char endC, String command)
    {
        int start = command.indexOf(startC);
        int end = command.indexOf(endC);

        if (start < 0 || end < 0)
        {
            throw new IllegalArgumentException("Unable to parse config: ('" + startC + "', '" + endC + "') missing.");
        }

        return command.substring(start + 1, end);
    }

    int getProviderDefaultSecurityStrength()
    {
        return providerDefaultSecurityStrength;
    }

    FipsDRBG.Base getProviderDefaultRandomBuilder()
    {
        return providerDefaultRandomBuilder;
    }

    public SecureRandom getDefaultSecureRandom()
    {
        SecureRandom defRandom;

        try
        {
            defRandom = CryptoServicesRegistrar.getSecureRandom();
        }
        catch (IllegalStateException e)
        {
            // See SP 800-90A R1 8.6.7 for setting of Nonce - at least 1/2 security strength bits
            synchronized (this)
            {
                if (providerDefaultRandom == null)
                {
                    SecureRandom sourceOfEntropy = getDefaultEntropySource();

                    // we set providerDefault here as we end up recursing due to personalization string
                    providerDefaultRandom = providerDefaultRandomBuilder
                        .fromEntropySource(sourceOfEntropy, true)
                        .setPersonalizationString(generatePersonalizationString())
                        .build(sourceOfEntropy.generateSeed((providerDefaultSecurityStrength / (2 * 8)) + 1), true, Strings.toByteArray("Bouncy Castle FIPS Provider"));
                }

                defRandom = providerDefaultRandom;
            }
        }

        synchronized (this)
        {
            // we only allow this value to go down as we want to avoid people getting the wrong idea
            // about a provider produced random they might have.
            if (defRandom instanceof FipsSecureRandom)
            {
                int securityStrength = ((FipsSecureRandom)defRandom).getSecurityStrength();

                if (securityStrength < providerDefaultRandomSecurityStrength)
                {
                    providerDefaultRandomSecurityStrength = securityStrength;
                }
            }
            else
            {
                providerDefaultRandomSecurityStrength = -1;     // unknown
            }
        }

        return defRandom;
    }

    SecureRandom getDefaultEntropySource()
    {
        // this has to be a lazy evaluation
        if (entropySource == null)
        {
            this.entropySource = AccessController.doPrivileged(new PrivilegedAction<SecureRandom>()
            {
                public SecureRandom run()
                {
                    if (hybridSource)
                    {
                        return new HybridSecureRandom();
                    }

                    return new CoreSecureRandom();
                }
            });
        }

        return entropySource;
    }

    /**
     * Return the default random security strength.
     *
     * @return the security strength for the default SecureRandom the provider uses.
     */
    public int getDefaultRandomSecurityStrength()
    {
        synchronized (this)
        {
            return providerDefaultRandomSecurityStrength;
        }
    }

    void addAttribute(String key, String attributeName, String attributeValue)
    {
        String attributeKey = key + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttribute(String type, ASN1ObjectIdentifier oid, String attributeName, String attributeValue)
    {
        String attributeKey = type + "." + oid + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttributes(String key, Map<String, String> attributes)
    {
        for (String attrName: attributes.keySet())
        {
            addAttribute(key, attrName, attributes.get(attrName));
        }
    }

    void addAttributes(String type, ASN1ObjectIdentifier oid, Map<String, String> attributes)
    {
        for (String attrName: attributes.keySet())
        {
            addAttribute(type, oid, attrName, attributes.get(attrName));
        }
    }

    void addAlgorithmImplementation(String key, String className, Map<String, String> attributes, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");
        addAttributes(key, attributes);

        put(key, className);
        creatorMap.put(className, creator);
    }

    void addAlgorithmImplementation(String key, String className, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");

        put(key, className);
        creatorMap.put(className, creator);
    }

    void addAlgorithmImplementation(String type, ASN1ObjectIdentifier oid, String className, EngineCreator creator)
    {
        String key1 = type + "." + oid;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttribute(type, oid, "ImplementedIn", "Software");

        put(key1, className);
        creatorMap.put(className, creator);

        addAlias(type, oid.getId(), "OID." + oid.getId());
    }

    void addAlgorithmImplementation(String type, ASN1ObjectIdentifier oid, String className,  Map<String, String> attributes, EngineCreator creator)
    {
        String key1 = type + "." + oid;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttributes(type, oid, attributes);
        addAttribute(type, oid, "ImplementedIn", "Software");

        put(key1, className);
        creatorMap.put(className, creator);

        addAlias(type, oid.getId(), "OID." + oid.getId());
    }

    void addAlias(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    void addAlias(String type, String name, String... aliases)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (String alias : aliases)
        {
            doPut("Alg.Alias." + type + "." + alias, name);
        }
    }

    void addAlias(String type, String name, ASN1ObjectIdentifier... oids)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (ASN1ObjectIdentifier oid : oids)
        {
            doPut("Alg.Alias." + type + "." + oid, name);
            doPut("Alg.Alias." + type + ".OID." + oid, name);
        }
    }

    private void doPut(String key, String name)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, name);
    }

    public synchronized final Service getService(String type, String algorithm)
    {
        String upperCaseAlgName = Strings.toUpperCase(algorithm);

        BcService service = serviceMap.get(type + "." + upperCaseAlgName);

        if (service == null)
        {
            String aliasString = "Alg.Alias." + type + ".";
            String realName = (String)this.get(aliasString + upperCaseAlgName);

            if (realName == null)
            {
                realName = upperCaseAlgName;
            }

            String className = (String)this.get(type + "." + realName);

            if (className == null)
            {
                return null;
            }

            String attributeKeyStart = type + "." + upperCaseAlgName + " ";

            List<String> aliases = new ArrayList<String>();
            Map<String, String> attributes = new HashMap<String, String>();

            for (Object key : this.keySet())
            {
                String sKey = (String)key;
                if (sKey.startsWith(aliasString))
                {
                    if (this.get(key).equals(algorithm))
                    {
                        aliases.add(sKey.substring(aliasString.length()));
                    }
                }
                if (sKey.startsWith(attributeKeyStart))
                {
                    attributes.put(sKey.substring(attributeKeyStart.length()), (String)this.get(sKey));
                }
            }

            service = new BcService(this, type, upperCaseAlgName, className, aliases, getAttributeMap(attributes), creatorMap.get(className));

            serviceMap.put(type + "." + upperCaseAlgName, service);
        }

        return service;
    }

    public synchronized final Set<Service> getServices()
    {
        Set<Service> serviceSet = super.getServices();
        Set<Service> bcServiceSet = new HashSet<Service>();

        for (Service service: serviceSet)
        {
            bcServiceSet.add(getService(service.getType(), service.getAlgorithm()));
        }

        return bcServiceSet;
    }

    void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
    {
        keyInfoConverters.put(oid, keyInfoConverter);
    }

    private byte[] generatePersonalizationString()
    {
        return Arrays.concatenate(Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private final Map<Map<String, String>, Map<String, String> > attributeMaps = new HashMap<Map<String, String>, Map<String, String>>();

    private Map<String, String> getAttributeMap(Map<String, String> attributeMap)
    {
        Map<String, String> attrMap = attributeMaps.get(attributeMap);
        if (attrMap != null)
        {
            return attrMap;
        }

        attributeMaps.put(attributeMap, attributeMap);

        return attributeMap;
    }

    private static boolean classExists(String className)
    {
        try
        {
            Class def = BouncyCastleFipsProvider.class.getClassLoader().loadClass(className);

            return def != null;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        AsymmetricKeyInfoConverter converter = keyInfoConverters.get(publicKeyInfo.getAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePublic(publicKeyInfo);
    }

    PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
        throws IOException
    {
        AsymmetricKeyInfoConverter converter = keyInfoConverters.get(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePrivate(privateKeyInfo);
    }

    private static class BcService
        extends Service
    {
        private final EngineCreator creator;

        /**
         * Construct a new service.
         *
         * @param provider   the provider that offers this service
         * @param type       the type of this service
         * @param algorithm  the algorithm name
         * @param className  the name of the class implementing this service
         * @param aliases    List of aliases or null if algorithm has no aliases
         * @param attributes Map of attributes or null if this implementation
         *                   has no attributes
         * @throws NullPointerException if provider, type, algorithm, or
         * className is null
         */
        public BcService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes, EngineCreator creator)
        {
            super(provider, type, algorithm, className, aliases, attributes);
            this.creator = creator;
        }

        public Object newInstance(Object constructorParameter)
            throws NoSuchAlgorithmException
        {
            try
            {
                FipsStatus.isReady();

                Object instance = creator.createInstance(constructorParameter);

                if (instance == null)
                {
                    throw new NoSuchAlgorithmException("No such algorithm in FIPS approved mode: " + getAlgorithm());
                }

                return instance;
            }
            catch (NoSuchAlgorithmException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new NoSuchAlgorithmException("Unable to invoke creator for " + getAlgorithm() + ": " + e.getMessage(), e);
            }
        }
    }

    private static class CoreSecureRandom
        extends SecureRandom
    {
        CoreSecureRandom()
        {
            super(new sun.security.provider.SecureRandom(), getSunProvider());
        }

        private static Provider getSunProvider()
        {
            try
            {
                Class provClass = Class.forName("sun.security.jca.Providers");

                Method method = provClass.getMethod("getSunProvider");

                return (Provider)method.invoke(provClass);
            }
            catch (Exception e)
            {
                return new sun.security.provider.Sun();
            }
        }
    }

    private static class HybridSecureRandom
        extends SecureRandom
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);
        private final SecureRandom baseRandom = new CoreSecureRandom();
        private final FipsSecureRandom drbg;

        HybridSecureRandom()
        {
            super(null, null);         // stop getDefaultRNG() call
            
            drbg = FipsDRBG.SHA512.fromEntropySource(new EntropySourceProvider()
                {
                    public EntropySource get(final int bitsRequired)
                    {
                        return new SignallingEntropySource(bitsRequired);
                    }
                })
                .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
                .build(baseRandom.generateSeed(32), false, null);     // 32 byte nonce
        }

        public void setSeed(byte[] seed)
        {
            if (drbg != null)
            {
                drbg.setSeed(seed);
            }
        }

        public void setSeed(long seed)
        {
            if (drbg != null)
            {
                drbg.setSeed(seed);
            }
        }
        
        public byte[] generateSeed(int numBytes)
        {
            byte[] data = new byte[numBytes];

            // after 20 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 20)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed();
                }
            }

            drbg.nextBytes(data);

            return data;
        }

        private class SignallingEntropySource
            implements EntropySource
        {
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            SignallingEntropySource(int bitsRequired)
            {
                this.byteLength = (bitsRequired + 7) / 8;
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = baseRandom.generateSeed(byteLength);
                }
                else
                {
                    scheduled.set(false);
                }

                if (!scheduled.getAndSet(true))
                {
                    new Thread(new EntropyGatherer(byteLength)).start();
                }

                return seed;
            }

            public int entropySize()
            {
                return byteLength * 8;
            }

            private class EntropyGatherer
                implements Runnable
            {
                private final int numBytes;

                EntropyGatherer(int numBytes)
                {
                    this.numBytes = numBytes;
                }

                public void run()
                {
                    entropy.set(baseRandom.generateSeed(numBytes));
                    seedAvailable.set(true);
                }
            }
        }
    }
}
