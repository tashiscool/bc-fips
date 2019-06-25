package org.bouncycastle.jcajce.provider;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BEROutputStream;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.OutputDigestCalculator;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.PBKD;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.jcajce.ConsistentKeyPair;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

class ProvPKCS12
    extends AsymmetricAlgorithmProvider
{
    private static final KeyIvSizeProvider sizeProvider = new KeyIvSizeProvider();

    static class KeyFactory
        extends BaseKDFSecretKeyFactory
    {
        private final String algName;
        private final int keySizeInBits;
        private final PasswordBasedDeriver.KeyType keyType;
        private final DigestAlgorithm prf;

        protected KeyFactory(String algName, DigestAlgorithm prf, PasswordBasedDeriver.KeyType keyType, int keySizeInBits)
        {
            this.algName = algName;
            this.prf = prf;
            this.keyType = keyType;
            this.keySizeInBits = keySizeInBits;
        }

        protected KeyFactory(String algName, PasswordBasedDeriver.KeyType keyType, int keySizeInBits)
        {
            this(algName, FipsSHS.Algorithm.SHA1, keyType, keySizeInBits);
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PBEKeySpec)
            {
                PBEKeySpec pbeKeySpec = (PBEKeySpec)keySpec;

                if (pbeKeySpec.getSalt() == null)
                {
                    throw new InvalidKeySpecException("Missing required salt");
                }

                return getSecretKey(prf, algName, pbeKeySpec, keyType, keySizeInBits);
            }

            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec.getClass().getName());
        }
    }

    static class GeneralKeyFactory
        extends BaseKDFSecretKeyFactory
    {
        private final String algName;
        private final FipsDigestAlgorithm prf;
        private final PasswordBasedDeriver.KeyType keyType;

        protected GeneralKeyFactory(String algName, FipsDigestAlgorithm prf, PasswordBasedDeriver.KeyType keyType)
        {
            this.algName = algName;
            this.prf = prf;
            this.keyType = keyType;
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PBEKeySpec)
            {
                PBEKeySpec pbeKeySpec = (PBEKeySpec)keySpec;

                if (pbeKeySpec.getSalt() == null)
                {
                    throw new InvalidKeySpecException("Missing required salt");
                }

                return getSecretKey(prf, algName, pbeKeySpec, keyType, pbeKeySpec.getKeyLength());
            }

            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec.getClass().getName());
        }
    }

    static SecretKey getSecretKey(DigestAlgorithm prf, String algName, PBEKeySpec pbeKeySpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits)
    {
        PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(
            PBKD.PKCS12.using(prf, PasswordConverter.PKCS12, pbeKeySpec.getPassword())
                .withIterationCount(pbeKeySpec.getIterationCount()).withSalt(pbeKeySpec.getSalt())
        );

        byte[] key = deriver.deriveKey(keyType, (keySizeInBits + 7) / 8);

        return new PBKDFPBEKey(key, algName, pbeKeySpec);
    }

    static byte[] getSecretKey(SecretKey pbeKey, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits)
    {
        PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(
            PBKD.PKCS12.using(FipsSHS.Algorithm.SHA1, pbeKey.getEncoded())
                .withIterationCount(pbeSpec.getIterationCount()).withSalt(pbeSpec.getSalt())
        );

        return deriver.deriveKey(keyType, (keySizeInBits + 7) / 8);
    }

    static byte[] getSecretKey(SecretKey pbeKey, DigestAlgorithm digest, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits)
    {
        PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(
            PBKD.PKCS12.using(digest, pbeKey.getEncoded())
                .withIterationCount(pbeSpec.getIterationCount()).withSalt(pbeSpec.getSalt())
        );

        return deriver.deriveKey(keyType, (keySizeInBits + 7) / 8);
    }

    static byte[][] getSecretKeyAndIV(SecretKey pbeKey, DigestAlgorithm digest, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits, int ivvSizeInBits)
    {
        PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(
            PBKD.PKCS12.using(digest, pbeKey.getEncoded())
                .withIterationCount(pbeSpec.getIterationCount()).withSalt(pbeSpec.getSalt())
        );

        return deriver.deriveKeyAndIV(keyType, (keySizeInBits + 7) / 8, (ivvSizeInBits + 7) / 8);
    }

    static class AlgParams
        extends BaseAlgorithmParameters
    {
        PKCS12PBEParams params;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return params.getEncoded(ASN1Encoding.DER);
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PBEParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new PBEParameterSpec(params.getIV(),
                    params.getIterations().intValue());
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PBEParameterSpec))
            {
                throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PBKDF-PKCS12 parameters algorithm parameters object");
            }

            PBEParameterSpec pbeSpec = (PBEParameterSpec)paramSpec;

            this.params = new PKCS12PBEParams(pbeSpec.getSalt(),
                pbeSpec.getIterationCount());
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            this.params = PKCS12PBEParams.getInstance(params);
        }

        protected String engineToString()
        {
            return "PBKDF-PKCS12 Parameters";
        }
    }

    private static class PKCS12KeyStoreSpi
        extends KeyStoreSpi
        implements PKCSObjectIdentifiers, X509ObjectIdentifiers
    {
        private static final int SALT_SIZE = 20;
        private static final int MIN_ITERATIONS = 1024;

        private IgnoresCaseHashtable privateKeyCache = new IgnoresCaseHashtable();
        private IgnoresCaseHashtable keys = new IgnoresCaseHashtable();
        private Hashtable localIds = new Hashtable();
        private IgnoresCaseHashtable certs = new IgnoresCaseHashtable();
        private Hashtable chainCerts = new Hashtable();
        private Hashtable keyCerts = new Hashtable();

        private boolean wrongPKCS12Zero = false;

        //
        // generic object types
        //
        static final int NULL = 0;
        static final int CERTIFICATE = 1;
        static final int KEY = 2;
        static final int SECRET = 3;
        static final int SEALED = 4;

        //
        // key types
        //
        static final int KEY_PRIVATE = 0;
        static final int KEY_PUBLIC = 1;
        static final int KEY_SECRET = 2;

        protected final SecureRandom random;

        // use of final causes problems with JDK 1.2 compiler
        private java.security.cert.CertificateFactory certFact;
        private BouncyCastleFipsProvider fipsProvider;
        private ASN1ObjectIdentifier keyAlgorithm;
        private ASN1ObjectIdentifier certAlgorithm;

        private class CertId
        {
            byte[] id;

            CertId(
                PublicKey key)
                throws IOException
            {
                this.id = createSubjectKeyId(key).getKeyIdentifier();
            }

            CertId(
                byte[] id)
            {
                this.id = id;
            }

            public int hashCode()
            {
                return Arrays.hashCode(id);
            }

            public boolean equals(
                Object o)
            {
                if (o == this)
                {
                    return true;
                }

                if (!(o instanceof CertId))
                {
                    return false;
                }

                CertId cId = (CertId)o;

                return Arrays.areEqual(id, cId.id);
            }
        }

        public PKCS12KeyStoreSpi(
            BouncyCastleFipsProvider fipsProvider,
            Provider certProvider,
            ASN1ObjectIdentifier keyAlgorithm,
            ASN1ObjectIdentifier certAlgorithm)
        {
            this.fipsProvider = fipsProvider;
            this.keyAlgorithm = keyAlgorithm;
            this.certAlgorithm = certAlgorithm;
            this.random = fipsProvider.getDefaultSecureRandom();

            try
            {
                if (certProvider != null)
                {
                    certFact = java.security.cert.CertificateFactory.getInstance("X.509", certProvider);
                }
                else
                {
                    certFact = java.security.cert.CertificateFactory.getInstance("X.509");
                }
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("can't create cert factory - " + e.toString());
            }
        }

        private SubjectKeyIdentifier createSubjectKeyId(
            PublicKey pubKey)
            throws IOException
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pubKey.getEncoded()));

            return new SubjectKeyIdentifier(getDigest(info));
        }

        private byte[] getDigest(SubjectPublicKeyInfo spki)
        {
            OutputDigestCalculator calculator = new FipsSHS.OperatorFactory<FipsSHS.Parameters>().createOutputDigestCalculator(FipsSHS.SHA1);

            calculator.getDigestStream().update(spki.getPublicKeyData().getBytes());

            return calculator.getDigest();
        }

        public Enumeration engineAliases()
        {
            Hashtable tab = new Hashtable();

            Enumeration e = certs.keys();
            while (e.hasMoreElements())
            {
                tab.put(e.nextElement(), "cert");
            }

            e = keys.keys();
            while (e.hasMoreElements())
            {
                String a = (String)e.nextElement();
                if (tab.get(a) == null)
                {
                    tab.put(a, "key");
                }
            }

            return tab.keys();
        }

        public boolean engineContainsAlias(
            String alias)
        {
            if (alias == null)
            {
                throw new NullPointerException("alias value is null");
            }
            return (certs.get(alias) != null || keys.get(alias) != null);
        }

        /**
         * this is not quite complete - we should follow up on the chain, a bit
         * tricky if a certificate appears in more than one chain so we rely on
         * the storage method to prune out orphaned chain certificates that we no
         * longer use.
         */
        public void engineDeleteEntry(
            String alias)
            throws KeyStoreException
        {
            Key k = (Key)keys.remove(alias);

            privateKeyCache.remove(alias);

            Certificate c = (Certificate)certs.remove(alias);

            if (c != null)
            {
                removeChainCert(c);
            }

            if (k != null)
            {
                String id = (String)localIds.remove(alias);
                if (id != null)
                {
                    c = (Certificate)keyCerts.remove(id);
                }
                if (c != null)
                {
                    removeChainCert(c);
                }
            }
        }

        private void removeChainCert(Certificate c)
            throws KeyStoreException
        {
            try
            {
                chainCerts.remove(new CertId(c.getPublicKey()));
            }
            catch (IOException e)
            {
                throw new KeyStoreException("Exception: " + e.getMessage(), e);
            }
        }

        /**
         * simply return the cert for the private key
         */
        public Certificate engineGetCertificate(
            String alias)
        {
            if (alias == null)
            {
                throw new IllegalArgumentException("null alias passed to getCertificate.");
            }

            Certificate c = (Certificate)certs.get(alias);

            //
            // look up the key table - and try the local key id
            //
            if (c == null)
            {
                String id = (String)localIds.get(alias);
                if (id != null)
                {
                    c = (Certificate)keyCerts.get(id);
                }
                else
                {
                    c = (Certificate)keyCerts.get(alias);
                }
            }

            return c;
        }

        public String engineGetCertificateAlias(
            Certificate cert)
        {
            Enumeration c = certs.elements();
            Enumeration k = certs.keys();

            while (c.hasMoreElements())
            {
                Certificate tc = (Certificate)c.nextElement();
                String ta = (String)k.nextElement();

                if (tc.equals(cert))
                {
                    return ta;
                }
            }

            c = keyCerts.elements();
            k = keyCerts.keys();

            while (c.hasMoreElements())
            {
                Certificate tc = (Certificate)c.nextElement();
                String ta = (String)k.nextElement();

                if (tc.equals(cert))
                {
                    return ta;
                }
            }

            return null;
        }

        public Certificate[] engineGetCertificateChain(
            String alias)
        {
            if (alias == null)
            {
                throw new IllegalArgumentException("null alias passed to getCertificateChain.");
            }

            if (!engineIsKeyEntry(alias))
            {
                return null;
            }

            Certificate c = engineGetCertificate(alias);

            if (c != null)
            {
                Vector cs = new Vector();

                while (c != null)
                {
                    X509Certificate x509c = (X509Certificate)c;
                    Certificate nextC = null;

                    byte[] bytes = x509c.getExtensionValue(Extension.authorityKeyIdentifier.getId());
                    if (bytes != null)
                    {
                        byte[] authBytes = ASN1OctetString.getInstance(bytes).getOctets();

                        AuthorityKeyIdentifier id = AuthorityKeyIdentifier.getInstance(authBytes);
                        if (id.getKeyIdentifier() != null)
                        {
                            nextC = (Certificate)chainCerts.get(new CertId(id.getKeyIdentifier()));
                        }
                    }

                    if (nextC == null)
                    {
                        //
                        // no authority key id, try the Issuer DN
                        //
                        Principal i = x509c.getIssuerDN();
                        Principal s = x509c.getSubjectDN();

                        if (!i.equals(s))
                        {
                            Enumeration e = chainCerts.keys();

                            while (e.hasMoreElements())
                            {
                                X509Certificate crt = (X509Certificate)chainCerts.get(e.nextElement());
                                Principal sub = crt.getSubjectDN();
                                if (sub.equals(i))
                                {
                                    try
                                    {
                                        x509c.verify(crt.getPublicKey());
                                        nextC = crt;
                                        break;
                                    }
                                    catch (Exception ex)
                                    {
                                        // continue
                                    }
                                }
                            }
                        }
                    }

                    if (cs.contains(c))
                    {
                        c = null;         // we've got a loop - stop now.
                    }
                    else
                    {
                        cs.addElement(c);
                        if (nextC != c)     // self signed - end of the chain
                        {
                            c = nextC;
                        }
                        else
                        {
                            c = null;
                        }
                    }
                }

                Certificate[] certChain = new Certificate[cs.size()];

                for (int i = 0; i != certChain.length; i++)
                {
                    certChain[i] = (Certificate)cs.elementAt(i);
                }

                return certChain;
            }

            return null;
        }

        public Date engineGetCreationDate(String alias)
        {
            if (alias == null)
            {
                throw new NullPointerException("alias == null");
            }
            if (keys.get(alias) == null && certs.get(alias) == null)
            {
                return null;
            }
            return new Date();
        }

        public Key engineGetKey(
            String alias,
            char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException
        {
            if (alias == null)
            {
                throw new IllegalArgumentException("null alias passed to getKey.");
            }

            Key key = (Key)keys.get(alias);

            try
            {
                // it's hard to imagine these things not being true, however we don't always get
                // to create these...
                if (key instanceof PrivateKey)
                {
                    if (privateKeyCache.get(alias) != null)
                    {
                        return key;
                    }

                    Certificate cert = engineGetCertificate(alias);

                    if (cert != null)
                    {
                        // check that the key pair and the certificate public key are consistent
                        // FSM_STATE:5.11,"IMPORTED KEY PAIR CONSISTENCY TEST", "The module is verifying the consistency of an imported key pair"
                        // FSM_TRANS:5.IKP.0,"CONDITIONAL TEST", "IMPORTED KEY PAIR CONSISTENCY TEST", "Invoke public/private key Consistency test on imported key pair"
                        new ConsistentKeyPair(cert.getPublicKey(), (PrivateKey)key);
                        // FSM_TRANS:5.IKP.1, "IMPORTED KEY PAIR CONSISTENCY TEST", "CONDITIONAL TEST", "Consistency test on imported key pair successful"
                        // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"

                        privateKeyCache.put(alias, key);
                    }
                }
            }
            catch (IllegalArgumentException e)
            {
                throw new UnrecoverableKeyException(e.getMessage());
            }

            return key;
        }

        public boolean engineIsCertificateEntry(
            String alias)
        {
            return (certs.get(alias) != null && keys.get(alias) == null);
        }

        public boolean engineIsKeyEntry(
            String alias)
        {
            return (keys.get(alias) != null);
        }

        public void engineSetCertificateEntry(
            String alias,
            Certificate cert)
            throws KeyStoreException
        {
            if (keys.get(alias) != null)
            {
                throw new KeyStoreException("There is a key entry with the name " + alias + ".");
            }

            certs.put(alias, cert);
            putChainCert(cert);
        }

        public void engineSetKeyEntry(
            String alias,
            byte[] key,
            Certificate[] chain)
            throws KeyStoreException
        {
            throw new KeyStoreException("operation not supported");
        }

        public void engineSetKeyEntry(
            String alias,
            Key key,
            char[] password,
            Certificate[] chain)
            throws KeyStoreException
        {
            if (!(key instanceof PrivateKey))
            {
                throw new KeyStoreException("PKCS12 does not support non-PrivateKeys");
            }

            if (chain == null)
            {
                throw new KeyStoreException("no certificate chain for private key");
            }

            if (keys.get(alias) != null)
            {
                engineDeleteEntry(alias);
            }

            try
            {
                // check that the key pair and the certificate public key are consistent
                // FSM_STATE:5.11,"IMPORTED KEY PAIR CONSISTENCY TEST", "The module is verifying the consistency of an imported key pair"
                // FSM_TRANS:5.IKP.0,"CONDITIONAL TEST", "IMPORTED KEY PAIR CONSISTENCY TEST", "Invoke public/private key Consistency test on imported key pair"
                new ConsistentKeyPair(chain[0].getPublicKey(), (PrivateKey)key);
                // FSM_TRANS:5.IKP.1, "IMPORTED KEY PAIR CONSISTENCY TEST", "CONDITIONAL TEST", "Consistency test on imported key pair successful"
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
            }
            catch (IllegalArgumentException e)
            {
                throw new KeyStoreException(e.getMessage());
            }

            keys.put(alias, key);
            privateKeyCache.put(alias, key);
            certs.put(alias, chain[0]);

            for (int i = 0; i != chain.length; i++)
            {
                putChainCert(chain[i]);
            }
        }

        private void putChainCert(Certificate c)
            throws KeyStoreException
        {
            try
            {
                chainCerts.put(new CertId(c.getPublicKey()), c);
            }
            catch (IOException e)
            {
                throw new KeyStoreException("Exception: " + e.getMessage(), e);
            }
        }

        public int engineSize()
        {
            Hashtable tab = new Hashtable();

            Enumeration e = certs.keys();
            while (e.hasMoreElements())
            {
                tab.put(e.nextElement(), "cert");
            }

            e = keys.keys();
            while (e.hasMoreElements())
            {
                String a = (String)e.nextElement();
                if (tab.get(a) == null)
                {
                    tab.put(a, "key");
                }
            }

            return tab.size();
        }

        public void engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam)
            throws KeyStoreException
        {
            if (entry instanceof KeyStore.PrivateKeyEntry)
            {
                super.engineSetEntry(alias, entry, new KeyStore.PasswordProtection(new char[0]));
            }
            else if (entry instanceof KeyStore.SecretKeyEntry)
            {
                throw new KeyStoreException("PKCS12 does not support storage of symmetric keys.");
            }
            else
            {
                super.engineSetEntry(alias, entry, null);
            }
        }

        protected PrivateKey unwrapKey(
            AlgorithmIdentifier algId,
            byte[] data,
            char[] password)
            throws IOException
        {
            ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
            try
            {
                Cipher cipher;
                if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
                {
                    cipher = createPKCS12Cipher(Cipher.UNWRAP_MODE, password, algId);
                }
                else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
                {
                    cipher = createPBES2Cipher(Cipher.UNWRAP_MODE, password, algId);
                }
                else
                {
                    throw new IOException("exception unwrapping private key - cannot recognize: " + algorithm);
                }

                // we pass "" as the key algorithm type as it is unknown at this point
                return (PrivateKey)cipher.unwrap(data, "", Cipher.PRIVATE_KEY);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (final Exception e)
            {
                throw new ProvIOException("exception unwrapping private key - " + e.toString(), e);
            }
        }

        protected byte[] wrapKey(
            AlgorithmIdentifier algId,
            Key key,
            char[] password)
            throws IOException
        {
            ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
            try
            {
                Cipher cipher;
                if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
                {
                    cipher = createPKCS12Cipher(Cipher.WRAP_MODE, password, algId);
                }
                else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
                {
                    cipher = createPBES2Cipher(Cipher.WRAP_MODE, password, algId);
                }
                else
                {
                    throw new IOException("exception unwrapping private key - cannot recognize: " + algorithm);
                }

                // we pass "" as the key algorithm type as it is unknown at this point
                return cipher.wrap(key);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (final Exception e)
            {
                throw new ProvIOException("exception unwrapping private key - " + e.toString(), e);
            }
        }

        protected byte[] cryptData(
            boolean forEncryption,
            AlgorithmIdentifier algId,
            char[] password,
            byte[] data)
            throws IOException
        {
            ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
            int mode = (forEncryption) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

            try
            {
                Cipher cipher;
                if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
                {
                    cipher = createPKCS12Cipher(mode, password, algId);
                }
                else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
                {
                    cipher = createPBES2Cipher(mode, password, algId);
                }
                else
                {
                    throw new IOException("unknown PBE algorithm: " + algorithm);
                }

                return cipher.doFinal(data);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (final Exception e)
            {
                throw new ProvIOException("exception decrypting data - " + e.toString(), e);
            }
        }

        private Cipher createPKCS12Cipher(int mode, char[] password, AlgorithmIdentifier algId)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
        {
            PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());

            Cipher cipher = Cipher.getInstance(algId.getAlgorithm().getId(), fipsProvider);

            cipher.init(mode, new PKCS12KeyWithParameters(password, wrongPKCS12Zero, pbeParams.getIV(), pbeParams.getIterations().intValue()));

            return cipher;
        }

        private Cipher createPBES2Cipher(int mode, char[] password, AlgorithmIdentifier algId)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
        {
            PBES2Parameters alg = PBES2Parameters.getInstance(algId.getParameters());
            PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(alg.getKeyDerivationFunc().getAlgorithm().getId(), fipsProvider);
            SecretKey key;

            if (func.isDefaultPrf())
            {
                key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(), func.getIterationCount().intValue(), sizeProvider.getKeySize(encScheme) * 8));
            }
            else
            {
                key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), func.getIterationCount().intValue(), sizeProvider.getKeySize(encScheme) * 8, func.getPrf()));
            }

            Cipher cipher = Cipher.getInstance(encScheme.getAlgorithm().getId());

            ASN1Encodable encParams = encScheme.getParameters();
            if (encParams instanceof ASN1OctetString)
            {
                cipher.init(mode, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
            }
            else
            {
                // TODO: at the moment it's just GOST, but...
                GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                cipher.init(mode, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
            }
            return cipher;
        }

        public void engineLoad(
            InputStream stream,
            char[] password)
            throws IOException
        {
            privateKeyCache.clear();

            if (stream == null)     // just initialising
            {
                return;
            }

            if (password == null)
            {
                throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
            }

            BufferedInputStream bufIn = new BufferedInputStream(stream);

            bufIn.mark(10);

            int head = bufIn.read();

            if (head != 0x30)
            {
                throw new IOException("stream does not represent a PKCS12 key store");
            }

            bufIn.reset();

            ASN1InputStream bIn = new ASN1InputStream(bufIn);
            ASN1Sequence obj = (ASN1Sequence)bIn.readObject();
            Pfx bag = Pfx.getInstance(obj);
            ContentInfo info = bag.getAuthSafe();
            Vector chain = new Vector();
            boolean unmarkedKey = false;

            if (bag.getMacData() != null)           // check the mac code
            {
                MacData mData = bag.getMacData();
                DigestInfo dInfo = mData.getMac();
                AlgorithmIdentifier algId = dInfo.getAlgorithmId();
                byte[] salt = mData.getSalt();
                int itCount = mData.getIterationCount().intValue();

                byte[] data = ((ASN1OctetString)info.getContent()).getOctets();

                try
                {
                    byte[] res = calculatePbeMac(algId, salt, itCount, password, data);
                    byte[] dig = dInfo.getDigest();

                    if (!Arrays.constantTimeAreEqual(res, dig))
                    {
                        if (password.length > 0)
                        {
                            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        }

                        // Try with incorrect zero length password
                        res = calculatePbeMacWrongZero(algId, salt, itCount, data);

                        if (!Arrays.constantTimeAreEqual(res, dig))
                        {
                            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        }

                        wrongPKCS12Zero = true;
                    }
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (final Exception e)
                {
                    throw new ProvIOException("error constructing MAC: " + e.toString(), e);
                }
            }

            keys = new IgnoresCaseHashtable();
            localIds = new Hashtable();

            if (info.getContentType().equals(data))
            {
                bIn = new ASN1InputStream(((ASN1OctetString)info.getContent()).getOctets());

                AuthenticatedSafe authSafe = AuthenticatedSafe.getInstance(bIn.readObject());
                ContentInfo[] c = authSafe.getContentInfo();

                for (int i = 0; i != c.length; i++)
                {
                    if (c[i].getContentType().equals(data))
                    {
                        ASN1InputStream dIn = new ASN1InputStream(((ASN1OctetString)c[i].getContent()).getOctets());
                        ASN1Sequence seq = (ASN1Sequence)dIn.readObject();

                        for (int j = 0; j != seq.size(); j++)
                        {
                            SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));
                            if (b.getBagId().equals(pkcs8ShroudedKeyBag))
                            {
                                org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo eIn = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getInstance(b.getBagValue());
                                PrivateKey privKey = unwrapKey(eIn.getEncryptionAlgorithm(), eIn.getEncryptedData(), password);

                                //
                                // set the attributes on the key
                                //
                                String alias = null;
                                ASN1OctetString localId = null;

                                if (b.getBagAttributes() != null)
                                {
                                    Enumeration e = b.getBagAttributes().getObjects();
                                    while (e.hasMoreElements())
                                    {
                                        ASN1Sequence sq = (ASN1Sequence)e.nextElement();
                                        ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier)sq.getObjectAt(0);
                                        ASN1Set attrSet = (ASN1Set)sq.getObjectAt(1);
                                        ASN1Primitive attr = null;

                                        if (attrSet.size() > 0)
                                        {
                                            attr = (ASN1Primitive)attrSet.getObjectAt(0);

                                            if (aOid.equals(pkcs_9_at_friendlyName))
                                            {
                                                if (alias != null && !alias.equals(DERBMPString.getInstance(attr).getString()))
                                                {
                                                    throw new IOException(
                                                        "attempt to add existing attribute with different value");
                                                }
                                                alias = DERBMPString.getInstance(attr).getString();
                                                keys.put(alias, privKey);
                                            }
                                            else if (aOid.equals(pkcs_9_at_localKeyId))
                                            {
                                                if (localId != null && !localId.equals(attr))
                                                {
                                                    throw new IOException(
                                                        "attempt to add existing attribute with different value");
                                                }
                                                localId = ASN1OctetString.getInstance(attr);
                                            }
                                        }
                                    }
                                }

                                if (localId != null)
                                {
                                    String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));

                                    if (alias == null)
                                    {
                                        keys.put(name, privKey);
                                    }
                                    else
                                    {
                                        localIds.put(alias, name);
                                    }
                                }
                                else
                                {
                                    unmarkedKey = true;
                                    keys.put("unmarked", privKey);
                                }
                            }
                            else if (b.getBagId().equals(certBag))
                            {
                                chain.addElement(b);
                            }
                            else
                            {
                                System.out.println("extra in data " + b.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(b));
                            }
                        }
                    }
                    else if (c[i].getContentType().equals(encryptedData))
                    {
                        EncryptedData d = EncryptedData.getInstance(c[i].getContent());
                        byte[] octets = cryptData(false, d.getEncryptionAlgorithm(), password, d.getContent().getOctets());
                        ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(octets);

                        for (int j = 0; j != seq.size(); j++)
                        {
                            SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));

                            if (b.getBagId().equals(certBag))
                            {
                                chain.addElement(b);
                            }
                            else if (b.getBagId().equals(pkcs8ShroudedKeyBag))
                            {
                                org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo eIn = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getInstance(b.getBagValue());
                                PrivateKey privKey = unwrapKey(eIn.getEncryptionAlgorithm(), eIn.getEncryptedData(), password);
                                String alias = null;
                                ASN1OctetString localId = null;

                                Enumeration e = b.getBagAttributes().getObjects();
                                while (e.hasMoreElements())
                                {
                                    ASN1Sequence sq = (ASN1Sequence)e.nextElement();
                                    ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier)sq.getObjectAt(0);
                                    ASN1Set attrSet = (ASN1Set)sq.getObjectAt(1);
                                    ASN1Primitive attr = null;

                                    if (attrSet.size() > 0)
                                    {
                                        attr = (ASN1Primitive)attrSet.getObjectAt(0);

                                        if (aOid.equals(pkcs_9_at_friendlyName))
                                        {
                                            if (alias != null && !alias.equals(DERBMPString.getInstance(attr).getString()))
                                            {
                                                throw new IOException(
                                                    "attempt to add existing attribute with different value");
                                            }
                                            alias = DERBMPString.getInstance(attr).getString();
                                            keys.put(alias, privKey);
                                        }
                                        else if (aOid.equals(pkcs_9_at_localKeyId))
                                        {
                                            if (localId != null && !localId.equals(attr))
                                            {
                                                throw new IOException(
                                                    "attempt to add existing attribute with different value");
                                            }
                                            localId = ASN1OctetString.getInstance(attr);
                                        }
                                    }
                                }

                                String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));

                                if (alias == null)
                                {
                                    keys.put(name, privKey);
                                }
                                else
                                {
                                    localIds.put(alias, name);
                                }
                            }
                            else if (b.getBagId().equals(keyBag))
                            {
                                org.bouncycastle.asn1.pkcs.PrivateKeyInfo kInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(b.getBagValue());
                                PrivateKey privKey = fipsProvider.getPrivateKey(kInfo);

                                String alias = null;
                                ASN1OctetString localId = null;

                                Enumeration e = b.getBagAttributes().getObjects();
                                while (e.hasMoreElements())
                                {
                                    ASN1Sequence sq = (ASN1Sequence)e.nextElement();
                                    ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier)sq.getObjectAt(0);
                                    ASN1Set attrSet = (ASN1Set)sq.getObjectAt(1);
                                    ASN1Primitive attr = null;

                                    if (attrSet.size() > 0)
                                    {
                                        attr = (ASN1Primitive)attrSet.getObjectAt(0);

                                        if (aOid.equals(pkcs_9_at_friendlyName))
                                        {
                                            if (alias != null && !alias.equals(DERBMPString.getInstance(attr).getString()))
                                            {
                                                throw new IOException(
                                                    "attempt to add existing attribute with different value");
                                            }
                                            alias = DERBMPString.getInstance(attr).getString();
                                            keys.put(alias, privKey);
                                        }
                                        else if (aOid.equals(pkcs_9_at_localKeyId))
                                        {
                                            if (localId != null && !localId.equals(attr))
                                            {
                                                throw new IOException(
                                                    "attempt to add existing attribute with different value");
                                            }
                                            localId = ASN1OctetString.getInstance(attr);
                                        }
                                    }
                                }

                                String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));

                                if (alias == null)
                                {
                                    keys.put(name, privKey);
                                }
                                else
                                {
                                    localIds.put(alias, name);
                                }
                            }
                            else
                            {
                                System.out.println("extra in encryptedData " + b.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(b));
                            }
                        }
                    }
                    else
                    {
                        System.out.println("extra " + c[i].getContentType().getId());
                        System.out.println("extra " + ASN1Dump.dumpAsString(c[i].getContent()));
                    }
                }
            }

            certs = new IgnoresCaseHashtable();
            chainCerts = new Hashtable();
            keyCerts = new Hashtable();

            for (int i = 0; i != chain.size(); i++)
            {
                SafeBag b = (SafeBag)chain.elementAt(i);
                CertBag cb = CertBag.getInstance(b.getBagValue());

                if (!cb.getCertId().equals(x509Certificate))
                {
                    throw new IOException("Unsupported certificate type: " + cb.getCertId());
                }

                Certificate cert;

                try
                {
                    ByteArrayInputStream cIn = new ByteArrayInputStream(
                        ((ASN1OctetString)cb.getCertValue()).getOctets());
                    cert = certFact.generateCertificate(cIn);
                }
                catch (final Exception e)
                {
                    throw new ProvIOException(e.toString(), e);
                }

                //
                // set the attributes
                //
                ASN1OctetString localId = null;
                String alias = null;

                if (b.getBagAttributes() != null)
                {
                    Enumeration e = b.getBagAttributes().getObjects();
                    while (e.hasMoreElements())
                    {
                        ASN1Sequence sq = (ASN1Sequence)e.nextElement();
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)sq.getObjectAt(0);
                        ASN1Primitive attr = (ASN1Primitive)((ASN1Set)sq.getObjectAt(1)).getObjectAt(0);

                        if (oid.equals(pkcs_9_at_friendlyName))
                        {
                            if (alias != null && !alias.equals(DERBMPString.getInstance(attr).getString()))
                            {
                                throw new IOException(
                                    "attempt to add existing attribute with different value");
                            }
                            alias = DERBMPString.getInstance(attr).getString();
                        }
                        else if (oid.equals(pkcs_9_at_localKeyId))
                        {
                            if (localId != null && !localId.equals(attr))
                            {
                                throw new IOException(
                                    "attempt to add existing attribute with different value");
                            }
                            localId = ASN1OctetString.getInstance(attr);
                        }
                    }
                }

                chainCerts.put(new CertId(cert.getPublicKey()), cert);

                if (unmarkedKey)
                {
                    if (keyCerts.isEmpty())
                    {
                        String name = Strings.fromByteArray(Hex.encode(createSubjectKeyId(cert.getPublicKey()).getKeyIdentifier()));

                        keyCerts.put(name, cert);
                        keys.put(name, keys.remove("unmarked"));
                    }
                }
                else
                {
                    //
                    // the local key id needs to override the friendly name
                    //
                    if (localId != null)
                    {
                        String name = Strings.fromByteArray(Hex.encode(localId.getOctets()));

                        keyCerts.put(name, cert);
                    }
                    if (alias != null)
                    {
                        certs.put(alias, cert);
                    }
                }
            }
        }

        public void engineStore(KeyStore.LoadStoreParameter param)
            throws IOException,
            NoSuchAlgorithmException, CertificateException
        {
            if (param == null)
            {
                throw new IllegalArgumentException("'param' arg cannot be null");
            }

            if (!(param instanceof PKCS12StoreParameter))
            {
                throw new IllegalArgumentException(
                    "No support for 'param' of type " + param.getClass().getName());
            }

            PKCS12StoreParameter bcParam = (PKCS12StoreParameter)param;

            char[] password;
            KeyStore.ProtectionParameter protParam = param.getProtectionParameter();
            if (protParam == null)
            {
                password = null;
            }
            else if (protParam instanceof KeyStore.PasswordProtection)
            {
                password = ((KeyStore.PasswordProtection)protParam).getPassword();
            }
            else
            {
                throw new IllegalArgumentException(
                    "No support for protection parameter of type " + protParam.getClass().getName());
            }

            doStore(bcParam.getOutputStream(), password, bcParam.isForDEREncoding());
        }

        public void engineStore(OutputStream stream, char[] password)
            throws IOException
        {
            doStore(stream, password, false);
        }

        private void doStore(OutputStream stream, char[] password, boolean useDEREncoding)
            throws IOException
        {
            if (password == null)
            {
                throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
            }

            //
            // handle the key
            //
            ASN1EncodableVector keyS = new ASN1EncodableVector();


            Enumeration ks = keys.keys();

            while (ks.hasMoreElements())
            {
                byte[] kSalt = new byte[SALT_SIZE];

                random.nextBytes(kSalt);

                String name = (String)ks.nextElement();
                PrivateKey privKey = (PrivateKey)keys.get(name);
                PKCS12PBEParams kParams = new PKCS12PBEParams(kSalt, MIN_ITERATIONS);
                AlgorithmIdentifier kAlgId = new AlgorithmIdentifier(keyAlgorithm, kParams);
                byte[] kBytes = wrapKey(kAlgId, privKey, password);

                org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo kInfo = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(kAlgId, kBytes);
                ASN1EncodableVector kName = new ASN1EncodableVector();

                //
                // set a default friendly name (from the key id) and local id
                //
                ASN1EncodableVector kSeq = new ASN1EncodableVector();
                Certificate ct = engineGetCertificate(name);

                kSeq.add(pkcs_9_at_localKeyId);
                kSeq.add(new DERSet(createSubjectKeyId(ct.getPublicKey())));

                kName.add(new DERSequence(kSeq));

                kSeq = new ASN1EncodableVector();

                kSeq.add(pkcs_9_at_friendlyName);
                kSeq.add(new DERSet(new DERBMPString(name)));

                kName.add(new DERSequence(kSeq));

                SafeBag kBag = new SafeBag(pkcs8ShroudedKeyBag, kInfo.toASN1Primitive(), new DERSet(kName));
                keyS.add(kBag);
            }

            byte[] keySEncoded = new DERSequence(keyS).getEncoded(ASN1Encoding.DER);
            BEROctetString keyString = new BEROctetString(keySEncoded);

            //
            // certificate processing
            //
            byte[] cSalt = new byte[SALT_SIZE];

            random.nextBytes(cSalt);

            ASN1EncodableVector certSeq = new ASN1EncodableVector();
            PKCS12PBEParams cParams = new PKCS12PBEParams(cSalt, MIN_ITERATIONS);
            AlgorithmIdentifier cAlgId = new AlgorithmIdentifier(certAlgorithm, cParams.toASN1Primitive());
            Hashtable doneCerts = new Hashtable();

            Enumeration cs = keys.keys();
            while (cs.hasMoreElements())
            {
                try
                {
                    String name = (String)cs.nextElement();
                    Certificate cert = engineGetCertificate(name);
                    boolean cAttrSet = false;
                    CertBag cBag = new CertBag(
                        x509Certificate,
                        new DEROctetString(cert.getEncoded()));
                    ASN1EncodableVector fName = new ASN1EncodableVector();

                    ASN1EncodableVector fSeq = new ASN1EncodableVector();

                    fSeq.add(pkcs_9_at_localKeyId);
                    fSeq.add(new DERSet(createSubjectKeyId(cert.getPublicKey())));
                    fName.add(new DERSequence(fSeq));

                    fSeq = new ASN1EncodableVector();

                    fSeq.add(pkcs_9_at_friendlyName);
                    fSeq.add(new DERSet(new DERBMPString(name)));

                    fName.add(new DERSequence(fSeq));

                    SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));

                    certSeq.add(sBag);

                    doneCerts.put(cert, cert);
                }
                catch (CertificateEncodingException e)
                {
                    throw new IOException("Error encoding certificate: " + e.toString());
                }
            }

            cs = certs.keys();
            while (cs.hasMoreElements())
            {
                try
                {
                    String certId = (String)cs.nextElement();
                    Certificate cert = (Certificate)certs.get(certId);
                    boolean cAttrSet = false;

                    if (keys.get(certId) != null)
                    {
                        continue;
                    }

                    CertBag cBag = new CertBag(
                        x509Certificate,
                        new DEROctetString(cert.getEncoded()));
                    ASN1EncodableVector fName = new ASN1EncodableVector();

                    ASN1EncodableVector fSeq = new ASN1EncodableVector();

                    fSeq.add(pkcs_9_at_friendlyName);
                    fSeq.add(new DERSet(new DERBMPString(certId)));

                    fName.add(new DERSequence(fSeq));

                    SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));

                    certSeq.add(sBag);

                    doneCerts.put(cert, cert);
                }
                catch (CertificateEncodingException e)
                {
                    throw new IOException("Error encoding certificate: " + e.toString());
                }
            }

            Set usedSet = getUsedCertificateSet();

            cs = chainCerts.keys();
            while (cs.hasMoreElements())
            {
                try
                {
                    CertId certId = (CertId)cs.nextElement();
                    Certificate cert = (Certificate)chainCerts.get(certId);

                    if (!usedSet.contains(cert))
                    {
                        continue;
                    }

                    if (doneCerts.get(cert) != null)
                    {
                        continue;
                    }

                    CertBag cBag = new CertBag(
                        x509Certificate,
                        new DEROctetString(cert.getEncoded()));
                    ASN1EncodableVector fName = new ASN1EncodableVector();

                    SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));

                    certSeq.add(sBag);
                }
                catch (CertificateEncodingException e)
                {
                    throw new IOException("Error encoding certificate: " + e.toString());
                }
            }

            byte[] certSeqEncoded = new DERSequence(certSeq).getEncoded(ASN1Encoding.DER);
            byte[] certBytes = cryptData(true, cAlgId, password, certSeqEncoded);
            EncryptedData cInfo = new EncryptedData(data, cAlgId, new BEROctetString(certBytes));

            ContentInfo[] info = new ContentInfo[]
                {
                    new ContentInfo(data, keyString),
                    new ContentInfo(encryptedData, cInfo.toASN1Primitive())
                };

            AuthenticatedSafe auth = new AuthenticatedSafe(info);

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            DEROutputStream asn1Out;
            if (useDEREncoding)
            {
                asn1Out = new DEROutputStream(bOut);
            }
            else
            {
                asn1Out = new BEROutputStream(bOut);
            }

            asn1Out.writeObject(auth);

            byte[] pkg = bOut.toByteArray();

            ContentInfo mainInfo = new ContentInfo(data, new BEROctetString(pkg));

            //
            // create the mac
            //
            byte[] mSalt = new byte[20];
            int itCount = MIN_ITERATIONS;

            random.nextBytes(mSalt);

            byte[] data = ((ASN1OctetString)mainInfo.getContent()).getOctets();

            MacData mData;

            try
            {
                AlgorithmIdentifier algId = new AlgorithmIdentifier(id_SHA1, DERNull.INSTANCE);
                byte[] res = calculatePbeMac(algId, mSalt, itCount, password, data);


                DigestInfo dInfo = new DigestInfo(algId, res);

                mData = new MacData(dInfo, mSalt, itCount);
            }
            catch (Exception e)
            {
                throw new IOException("error constructing MAC: " + e.toString());
            }

            //
            // output the Pfx
            //
            Pfx pfx = new Pfx(mainInfo, mData);

            if (useDEREncoding)
            {
                asn1Out = new DEROutputStream(stream);
            }
            else
            {
                asn1Out = new BEROutputStream(stream);
            }

            asn1Out.writeObject(pfx);
        }

        private byte[] calculatePbeMacWrongZero(
            AlgorithmIdentifier algID,
            byte[] salt,
            int itCount,
            byte[] data)
            throws Exception
        {
            byte[] derivedKey = getDerivedMacKey(algID, new byte[2], salt, itCount);

            String algOID = algID.getAlgorithm().getId();
            Mac mac = Mac.getInstance(algOID, fipsProvider);

            mac.init(new SecretKeySpec(derivedKey, algOID));
            mac.update(data);

            return mac.doFinal();
        }

        private byte[] calculatePbeMac(
            AlgorithmIdentifier algID,
            byte[] salt,
            int itCount,
            char[] password,
            byte[] data)
            throws Exception
        {
            byte[] derivedKey = getDerivedMacKey(algID, PasswordConverter.PKCS12.convert(password), salt, itCount);

            String algOID = algID.getAlgorithm().getId();
            Mac mac = Mac.getInstance(algOID, fipsProvider);

            mac.init(new SecretKeySpec(derivedKey, algOID));
            mac.update(data);

            return mac.doFinal();
        }

        private byte[] getDerivedMacKey(AlgorithmIdentifier algID, byte[] password, byte[] salt, int itCount)
        {
            PasswordBasedDeriver deriver;
            int keySize;

            if (algID.getAlgorithm().equals(CryptoProObjectIdentifiers.gostR3411))
            {
                deriver = new PBKD.DeriverFactory().createDeriver(
                    PBKD.PKCS12.using(SecureHash.Algorithm.GOST3411, password)
                        .withSalt(salt)
                        .withIterationCount(itCount)
                );
                keySize = 256 / 8;
            }
            else if (algID.getAlgorithm().equals(NISTObjectIdentifiers.id_sha224))
            {
                deriver = new PBKD.DeriverFactory().createDeriver(
                    PBKD.PKCS12.using(FipsSHS.Algorithm.SHA224, password)
                        .withSalt(salt)
                        .withIterationCount(itCount)
                );
                keySize = 224 / 8;
            }
            else if (algID.getAlgorithm().equals(NISTObjectIdentifiers.id_sha256))
            {
                deriver = new PBKD.DeriverFactory().createDeriver(
                    PBKD.PKCS12.using(FipsSHS.Algorithm.SHA256, password)
                        .withSalt(salt)
                        .withIterationCount(itCount)
                );
                keySize = 256 / 8;
            }
            else
            {
                deriver = new PBKD.DeriverFactory().createDeriver(
                    PBKD.PKCS12.using(FipsSHS.Algorithm.SHA1, password)
                        .withSalt(salt)
                        .withIterationCount(itCount)
                );
                keySize = 20;
            }

            return deriver.deriveKey(PasswordBasedDeriver.KeyType.MAC, keySize);
        }

        private static class IgnoresCaseHashtable
        {
            private Hashtable orig = new Hashtable();
            private Hashtable keys = new Hashtable();

            public void put(String key, Object value)
            {
                String lower = Strings.toLowerCase(key);
                String k = (String)keys.get(lower);
                if (k != null)
                {
                    orig.remove(k);
                }

                keys.put(lower, key);
                orig.put(key, value);
            }

            public Enumeration keys()
            {
                return orig.keys();
            }

            public Object remove(String alias)
            {
                if (alias == null)
                {
                    return null;
                }

                String k = (String)keys.remove(Strings.toLowerCase(alias));
                if (k == null)
                {
                    return null;
                }

                return orig.remove(k);
            }

            public Object get(String alias)
            {
                if (alias == null)
                {
                    return null;
                }

                String k = (String)keys.get(Strings.toLowerCase(alias));
                if (k == null)
                {
                    return null;
                }

                return orig.get(k);
            }

            public Enumeration elements()
            {
                return orig.elements();
            }

            public void clear()
            {
                orig.clear();
            }
        }

        private Set getUsedCertificateSet()
        {
            Set usedSet = new HashSet();

            for (Enumeration en = keys.keys(); en.hasMoreElements();)
            {
                String alias = (String)en.nextElement();

                    Certificate[] certs = engineGetCertificateChain(alias);

                    for (int i = 0; i != certs.length; i++)
                    {
                        usedSet.add(certs[i]);
                    }
            }

            for (Enumeration en = certs.keys(); en.hasMoreElements();)
            {
                String alias = (String)en.nextElement();

                Certificate cert = engineGetCertificate(alias);

                usedSet.add(cert);
            }

            return usedSet;
        }
    }

    private static class BCPKCS12KeyStore3DES40BitRC2
        extends PKCS12KeyStoreSpi
    {
        public BCPKCS12KeyStore3DES40BitRC2(BouncyCastleFipsProvider fipsProvider)
        {
            super(fipsProvider, fipsProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC);
        }
    }

    private static class BCPKCS12KeyStore3DES
        extends PKCS12KeyStoreSpi
    {
        public BCPKCS12KeyStore3DES(BouncyCastleFipsProvider fipsProvider)
        {
            super(fipsProvider, fipsProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
        }
    }

    private static class DefPKCS12KeyStore3DES40BitRC2
        extends PKCS12KeyStoreSpi
    {
        public DefPKCS12KeyStore3DES40BitRC2(BouncyCastleFipsProvider fipsProvider)
        {
            super(fipsProvider, null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC);
        }
    }

    private static class DefPKCS12KeyStore3DES
        extends PKCS12KeyStoreSpi
    {
        public DefPKCS12KeyStore3DES(BouncyCastleFipsProvider fipsProvider)
        {
            super(fipsProvider, null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
        }
    }

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.keystore" + ".pkcs12.";

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyStore.PKCS12", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore3DES", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BCPKCS12KeyStore3DES(provider);
            }
        });
        provider.addAlias("Alg.Alias.KeyStore.BCPKCS12", "PKCS12");
        provider.addAlias("Alg.Alias.KeyStore.PKCS12-3DES-3DES", "PKCS12");

        provider.addAlgorithmImplementation("KeyStore.PKCS12-DEF", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore3DES", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new DefPKCS12KeyStore3DES(provider);
            }
        });
        provider.addAlias("Alg.Alias.KeyStore.PKCS12-DEF-3DES-3DES", "PKCS12-DEF");

        provider.addAlgorithmImplementation("KeyStore.PKCS12-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BCPKCS12KeyStore3DES40BitRC2(provider);
            }
        }));

        provider.addAlgorithmImplementation("KeyStore.PKCS12-DEF-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new DefPKCS12KeyStore3DES40BitRC2(provider);
            }
        }));

        provider.addAlgorithmImplementation("AlgorithmParameters.PBKDF-PKCS12", PREFIX + "PKCS12AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));
        provider.addAlgorithmImplementation("AlgorithmParameters.PBKDF-PKCS12WITHSHA256", PREFIX + "PKCS12SHA256AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));
        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF-PKCS12", PREFIX + "PKCS12SecKeyFact", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new GeneralKeyFactory("PBKDF-PKCS12withSHA1", FipsSHS.Algorithm.SHA1, PasswordBasedDeriver.KeyType.CIPHER);
            }
        }));
        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF-PKCS12WITHSHA256", PREFIX + "PKCS12SHA256SecKeyFact", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new GeneralKeyFactory("PBKDF-PKCS12withSHA256", FipsSHS.Algorithm.SHA256, PasswordBasedDeriver.KeyType.CIPHER);
            }
        }));
    }
}
