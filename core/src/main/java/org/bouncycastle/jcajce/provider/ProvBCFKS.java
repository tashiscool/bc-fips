package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.EncryptedObjectStoreData;
import org.bouncycastle.asn1.bc.EncryptedPrivateKeyData;
import org.bouncycastle.asn1.bc.EncryptedSecretKeyData;
import org.bouncycastle.asn1.bc.ObjectData;
import org.bouncycastle.asn1.bc.ObjectDataSequence;
import org.bouncycastle.asn1.bc.ObjectStore;
import org.bouncycastle.asn1.bc.ObjectStoreData;
import org.bouncycastle.asn1.bc.ObjectStoreIntegrityCheck;
import org.bouncycastle.asn1.bc.PbkdMacIntegrityCheck;
import org.bouncycastle.asn1.bc.SecretKeyData;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.OutputAEADDecryptor;
import org.bouncycastle.crypto.OutputAEADEncryptor;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.fips.FipsPBKD;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.jcajce.ConsistentKeyPair;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

class ProvBCFKS
    extends AlgorithmProvider
{
    private static final Map<String, ASN1ObjectIdentifier> oidMap = new HashMap<String, ASN1ObjectIdentifier>();
    private static final Map<ASN1ObjectIdentifier, String> publicAlgMap = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        // Note: AES handled inline
        oidMap.put("DESEDE", OIWObjectIdentifiers.desEDE);
        oidMap.put("TRIPLEDES", OIWObjectIdentifiers.desEDE);
        oidMap.put("TDEA", OIWObjectIdentifiers.desEDE);
        oidMap.put("HMACSHA1", PKCSObjectIdentifiers.id_hmacWithSHA1);
        oidMap.put("HMACSHA224", PKCSObjectIdentifiers.id_hmacWithSHA224);
        oidMap.put("HMACSHA256", PKCSObjectIdentifiers.id_hmacWithSHA256);
        oidMap.put("HMACSHA384", PKCSObjectIdentifiers.id_hmacWithSHA384);
        oidMap.put("HMACSHA512", PKCSObjectIdentifiers.id_hmacWithSHA512);

        publicAlgMap.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        publicAlgMap.put(X9ObjectIdentifiers.id_ecPublicKey, "EC");
        publicAlgMap.put(OIWObjectIdentifiers.elGamalAlgorithm, "DH");
        publicAlgMap.put(PKCSObjectIdentifiers.dhKeyAgreement, "DH");
        publicAlgMap.put(X9ObjectIdentifiers.id_dsa, "DSA");
    }

    private static String getPublicKeyAlg(ASN1ObjectIdentifier oid)
    {
        String algName = publicAlgMap.get(oid);

        if (algName != null)
        {
            return algName;
        }

        return oid.getId();
    }

    private static class BCFIPSKeyStoreSpi
        extends KeyStoreSpi
    {
        private final static BigInteger CERTIFICATE = BigInteger.valueOf(0);
        private final static BigInteger PRIVATE_KEY = BigInteger.valueOf(1);
        private final static BigInteger SECRET_KEY = BigInteger.valueOf(2);
        private final static BigInteger PROTECTED_PRIVATE_KEY = BigInteger.valueOf(3);
        private final static BigInteger PROTECTED_SECRET_KEY = BigInteger.valueOf(4);

        private final BouncyCastleFipsProvider fipsProvider;
        private final Map<String, ObjectData> entries = new HashMap<String, ObjectData>();
        private final Map<String, PrivateKey> privateKeyCache = new HashMap<String, PrivateKey>();

        private AlgorithmIdentifier hmacAlgorithm;
        private KeyDerivationFunc hmacPkbdAlgorithm;
        private Date  creationDate;
        private Date  lastModifiedDate;

        BCFIPSKeyStoreSpi(BouncyCastleFipsProvider fipsProvider)
        {
            this.fipsProvider = fipsProvider;
        }

        @Override
        public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException
        {
            ObjectData ent = entries.get(alias);

            if (ent != null)
            {
                if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
                {
                    PrivateKey cachedKey = privateKeyCache.get(alias);
                    if (cachedKey != null)
                    {
                        return cachedKey;
                    }

                    EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                    EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfo.getInstance(encPrivData.getEncryptedPrivateKeyInfo());

                    try
                    {
                        PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(decryptData("PRIVATE_KEY_ENCRYPTION", encInfo.getEncryptionAlgorithm(), password, encInfo.getEncryptedData()));

                        KeyFactory kFact;
                        if (fipsProvider != null)
                        {
                            kFact = KeyFactory.getInstance(pInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(), fipsProvider);
                        }
                        else
                        {
                            kFact = KeyFactory.getInstance(getPublicKeyAlg(pInfo.getPrivateKeyAlgorithm().getAlgorithm()));
                        }

                        PrivateKey privateKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(pInfo.getEncoded()));

                        // check that the key pair and the certificate public key are consistent
                        // FSM_STATE:5.11,"IMPORTED KEY PAIR CONSISTENCY TEST", "The module is verifying the consistency of an imported key pair"
                        // FSM_TRANS:5.IKP.0,"CONDITIONAL TEST", "IMPORTED KEY PAIR CONSISTENCY TEST", "Invoke public/private key Consistency test on imported key pair"
                        new ConsistentKeyPair(engineGetCertificate(alias).getPublicKey(), privateKey);
                        // FSM_TRANS:5.IKP.1, "IMPORTED KEY PAIR CONSISTENCY TEST", "CONDITIONAL TEST", "Consistency test on imported key pair successful"
                        // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"

                        privateKeyCache.put(alias, privateKey);

                        return privateKey;
                    }
                    catch (Exception e)
                    {
                        throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover private key (" + alias + "): " + e.getMessage());
                    }
                }
                else if (ent.getType().equals(SECRET_KEY) || ent.getType().equals(PROTECTED_SECRET_KEY))
                {
                    EncryptedSecretKeyData encKeyData = EncryptedSecretKeyData.getInstance(ent.getData());

                    try
                    {
                        SecretKeyData keyData = SecretKeyData.getInstance(decryptData("SECRET_KEY_ENCRYPTION", encKeyData.getKeyEncryptionAlgorithm(), password, encKeyData.getEncryptedKeyData()));
                        SecretKeyFactory kFact;
                        if (fipsProvider != null)
                        {
                            kFact = SecretKeyFactory.getInstance(keyData.getKeyAlgorithm().getId(), fipsProvider);
                        }
                        else
                        {
                            kFact = SecretKeyFactory.getInstance(keyData.getKeyAlgorithm().getId());
                        }

                        return kFact.generateSecret(new SecretKeySpec(keyData.getKeyBytes(), keyData.getKeyAlgorithm().getId()));
                    }
                    catch (Exception e)
                    {
                        throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + alias + "): " + e.getMessage());
                    }
                }
                else
                {
                    throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + alias + "): type not recognized");
                }
            }

            return null;
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias)
        {
            ObjectData ent = entries.get(alias);

            if (ent != null)
            {
                if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
                {
                    EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                    org.bouncycastle.asn1.x509.Certificate[] certificates = encPrivData.getCertificateChain();
                    Certificate[] chain = new X509Certificate[certificates.length];

                    for (int i = 0; i != chain.length; i++)
                    {
                        chain[i] = decodeCertificate(certificates[i]);
                    }

                    return chain;
                }
            }

            return null;
        }

        @Override
        public Certificate engineGetCertificate(String s)
        {
            ObjectData ent = entries.get(s);

            if (ent != null)
            {
                if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
                {
                    EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                    org.bouncycastle.asn1.x509.Certificate[] certificates = encPrivData.getCertificateChain();

                    return decodeCertificate(certificates[0]);
                }
                else if (ent.getType().equals(CERTIFICATE))
                {
                    return decodeCertificate(ent.getData());
                }
            }

            return null;
        }

        private Certificate decodeCertificate(Object cert)
        {
            try
            {
                if (fipsProvider != null)
                {
                    return new X509CertificateObject(fipsProvider, org.bouncycastle.asn1.x509.Certificate.getInstance(cert));
                }
                else
                {
                    try
                    {
                        java.security.cert.CertificateFactory certFact = CertificateFactory.getInstance("X.509");

                        return certFact.generateCertificate(new ByteArrayInputStream(org.bouncycastle.asn1.x509.Certificate.getInstance(cert).getEncoded()));
                    }
                    catch (Exception e)
                    {
                        return new X509CertificateObject(null, org.bouncycastle.asn1.x509.Certificate.getInstance(cert));
                    }
                }
            }
            catch (CertificateParsingException e)
            {
                return null; // can't extract!
            }
        }

        @Override
        public Date engineGetCreationDate(String s)
        {
            ObjectData ent = entries.get(s);

            if (ent != null)
            {
                try
                {
                    // we return last modified as it represents date current state of entry was created
                    return ent.getLastModifiedDate().getDate();
                }
                catch (ParseException e)
                {
                    return new Date();     // it's here, but...
                }
            }

            return null;
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException
        {
            Date creationDate = new Date();
            Date lastEditDate = creationDate;

            ObjectData entry = entries.get(alias);
            if (entry != null)
            {
                creationDate = extractCreationDate(entry, creationDate);
            }

            privateKeyCache.remove(alias);

            if (key instanceof PrivateKey)
            {
                if (chain == null)
                {
                    throw new KeyStoreException("BCFKS KeyStore requires a certificate chain for private key storage.");
                }

                try
                {
                    // check that the key pair and the certificate public are consistent
                    // FSM_STATE:5.11,"IMPORTED KEY PAIR CONSISTENCY TEST", "The module is verifying the consistency of an imported key pair"
                    // FSM_TRANS:5.IKP.0,"CONDITIONAL TEST", "IMPORTED KEY PAIR CONSISTENCY TEST", "Invoke public/private key Consistency test on imported key pair"
                    new ConsistentKeyPair(chain[0].getPublicKey(), (PrivateKey)key);
                    // FSM_TRANS:5.IKP.1, "IMPORTED KEY PAIR CONSISTENCY TEST", "CONDITIONAL TEST", "Consistency test on imported key pair successful"
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"

                    byte[] encodedKey = key.getEncoded();

                    KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(256 / 8);
                    byte[] keyBytes = generateKey(pbkdAlgId, "PRIVATE_KEY_ENCRYPTION", ((password != null) ? password : new char[0]));

                    FipsAES.AEADOperatorFactory opFact = new FipsAES.AEADOperatorFactory();
                    FipsAES.AuthParameters      aeadParams = FipsAES.CCM.withIV(getDefaultSecureRandom());
                    OutputAEADEncryptor         encryptor = opFact.createOutputAEADEncryptor(new SymmetricSecretKey(FipsAES.CCM, keyBytes), aeadParams);

                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                    OutputStream encOut = encryptor.getEncryptingStream(bOut);

                    encOut.write(encodedKey);

                    encOut.close();

                    PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, new CCMParameters(aeadParams.getIV(), aeadParams.getMACSizeInBits() / 8)));

                    EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pbeParams), bOut.toByteArray());

                    EncryptedPrivateKeyData keySeq = createPrivateKeySequence(keyInfo, chain);

                    entries.put(alias, new ObjectData(PRIVATE_KEY, alias, creationDate, lastEditDate, keySeq.getEncoded(), null));
                }
                catch (Exception e)
                {
                    throw new KeyStoreException("BCFKS KeyStore exception storing private key: " + e.toString(), e);
                }
            }
            else if (key instanceof SecretKey)
            {
                if (chain != null)
                {
                    throw new KeyStoreException("BCFKS KeyStore cannot store certificate chain with secret key.");
                }

                try
                {
                    byte[] encodedKey = key.getEncoded();

                    KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(256 / 8);
                    byte[] keyBytes = generateKey(pbkdAlgId, "SECRET_KEY_ENCRYPTION", ((password != null) ? password : new char[0]));

                    FipsAES.AEADOperatorFactory opFact = new FipsAES.AEADOperatorFactory();
                    FipsAES.AuthParameters      aeadParams = FipsAES.CCM.withIV(getDefaultSecureRandom());
                    OutputAEADEncryptor         encryptor = opFact.createOutputAEADEncryptor(new SymmetricSecretKey(FipsAES.CCM, keyBytes), aeadParams);

                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                    OutputStream encOut = encryptor.getEncryptingStream(bOut);
                    String       keyAlg = Strings.toUpperCase(key.getAlgorithm());

                    if (keyAlg.contains("AES"))
                    {
                        encOut.write(new SecretKeyData(NISTObjectIdentifiers.aes, encodedKey).getEncoded());
                    }
                    else
                    {
                        ASN1ObjectIdentifier algOid = oidMap.get(keyAlg);
                        if (algOid != null)
                        {
                            encOut.write(new SecretKeyData(algOid, encodedKey).getEncoded());
                        }
                        else
                        {
                            throw new KeyStoreException("BCFKS KeyStore cannot recognize secret key (" + keyAlg + ") for storage.");
                        }
                    }

                    encOut.close();

                    PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, new CCMParameters(aeadParams.getIV(), aeadParams.getMACSizeInBits() / 8)));

                    EncryptedSecretKeyData keyData = new EncryptedSecretKeyData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pbeParams), bOut.toByteArray());

                    entries.put(alias, new ObjectData(SECRET_KEY, alias, creationDate, lastEditDate, keyData.getEncoded(), null));
                }
                catch (Exception e)
                {
                    throw new KeyStoreException("BCFKS KeyStore exception storing private key: " + e.toString(), e);
                }
            }
            else
            {
                throw new KeyStoreException("BCFKS KeyStore unable to recognize key.");
            }

            lastModifiedDate = lastEditDate;
        }

        private SecureRandom getDefaultSecureRandom()
        {
            if (fipsProvider != null)
            {
                return fipsProvider.getDefaultSecureRandom();
            }
            else
            {
                return new SecureRandom();
            }
        }

        private EncryptedPrivateKeyData createPrivateKeySequence(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, Certificate[] chain)
            throws CertificateEncodingException
        {
            org.bouncycastle.asn1.x509.Certificate[] certChain = new org.bouncycastle.asn1.x509.Certificate[chain.length];
            for (int i = 0; i != chain.length; i++)
            {
                certChain[i] = org.bouncycastle.asn1.x509.Certificate.getInstance(chain[i].getEncoded());
            }

            return new EncryptedPrivateKeyData(encryptedPrivateKeyInfo, certChain);
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] keyBytes, Certificate[] chain)
            throws KeyStoreException
        {
            Date creationDate = new Date();
            Date lastEditDate = creationDate;

            ObjectData entry = entries.get(alias);
            if (entry != null)
            {
                creationDate = extractCreationDate(entry, creationDate);
            }

            if (chain != null)
            {
                EncryptedPrivateKeyInfo encInfo;

                try
                {
                    encInfo = EncryptedPrivateKeyInfo.getInstance(keyBytes);
                }
                catch (Exception e)
                {
                    throw new KeyStoreException("BCFKS KeyStore private key encoding must be an EncryptedPrivateKeyInfo.", e);
                }

                try
                {
                    privateKeyCache.remove(alias);
                    entries.put(alias, new ObjectData(PROTECTED_PRIVATE_KEY, alias, creationDate, lastEditDate, createPrivateKeySequence(encInfo, chain).getEncoded(), null));
                }
                catch (Exception e)
                {
                    throw new KeyStoreException("BCFKS KeyStore exception storing protected private key: " + e.toString(), e);
                }
            }
            else
            {
                try
                {
                    entries.put(alias, new ObjectData(PROTECTED_SECRET_KEY, alias, creationDate, lastEditDate, keyBytes, null));
                }
                catch (Exception e)
                {
                    throw new KeyStoreException("BCFKS KeyStore exception storing protected private key: " + e.toString(), e);
                }
            }

            lastModifiedDate = lastEditDate;
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate certificate)
            throws KeyStoreException
        {
            ObjectData  entry =  entries.get(alias);
            Date        creationDate = new Date();
            Date        lastEditDate = creationDate;

            if (entry != null)
            {
                if (!entry.getType().equals(CERTIFICATE))
                {
                    throw new KeyStoreException("BCFKS KeyStore already has a key entry with alias " + alias);
                }

                creationDate = extractCreationDate(entry, creationDate);
            }

            try
            {
                entries.put(alias, new ObjectData(CERTIFICATE, alias, creationDate, lastEditDate, certificate.getEncoded(), null));
            }
            catch (CertificateEncodingException e)
            {
                throw new KeyStoreException("BCFKS KeyStore unable to handle certificate: " + e.getMessage(), e);
            }

            lastModifiedDate = lastEditDate;
        }

        private Date extractCreationDate(ObjectData entry, Date creationDate)
        {
            try
            {
                creationDate = entry.getCreationDate().getDate();
            }
            catch (ParseException e)
            {
                // this should never happen, if it does we'll leave creation date unmodified and hope for the best.
            }
            return creationDate;
        }

        @Override
        public void engineDeleteEntry(String alias)
            throws KeyStoreException
        {
            ObjectData  entry = entries.get(alias);

            if (entry == null)
            {
                return;
            }

            privateKeyCache.remove(alias);
            entries.remove(alias);

            lastModifiedDate = new Date();
        }

        @Override
        public Enumeration<String> engineAliases()
        {
            final Iterator<String> it = new HashSet(entries.keySet()).iterator();

            return new Enumeration<String>()
            {
                public boolean hasMoreElements()
                {
                    return it.hasNext();
                }

                public String nextElement()
                {
                    return it.next();
                }
            };
        }

        @Override
        public boolean engineContainsAlias(String alias)
        {
            if (alias == null)
            {
                throw new NullPointerException("alias value is null");
            }

            return entries.containsKey(alias);
        }

        @Override
        public int engineSize()
        {
            return entries.size();
        }

        @Override
        public boolean engineIsKeyEntry(String alias)
        {
            ObjectData ent = entries.get(alias);

            if (ent != null)
            {
                BigInteger entryType = ent.getType();
                return entryType.equals(PRIVATE_KEY) || entryType.equals(SECRET_KEY)
                    || entryType.equals(PROTECTED_PRIVATE_KEY) || entryType.equals(PROTECTED_SECRET_KEY);
            }

            return false;
        }

        @Override
        public boolean engineIsCertificateEntry(String alias)
        {
            ObjectData ent = entries.get(alias);

            if (ent != null)
            {
                return ent.getType().equals(CERTIFICATE);
            }

            return false;
        }

        @Override
        public String engineGetCertificateAlias(Certificate certificate)
        {
            if (certificate == null)
            {
                return null;
            }

            byte[] encodedCert;
            try
            {
                encodedCert = certificate.getEncoded();
            }
            catch (CertificateEncodingException e)
            {
                return null;
            }

            for (Iterator<String> it = entries.keySet().iterator(); it.hasNext();)
            {
                String alias = it.next();
                ObjectData ent = entries.get(alias);

                if (ent.getType().equals(CERTIFICATE))
                {
                    if (Arrays.areEqual(ent.getData(), encodedCert))
                    {
                        return alias;
                    }
                }
                else if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
                {
                    try
                    {
                        EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                        if (Arrays.areEqual(encPrivData.getCertificateChain()[0].toASN1Primitive().getEncoded(), encodedCert))
                        {
                            return alias;
                        }
                    }
                    catch (IOException e)
                    {
                        // ignore - this should never happen
                    }
                }
            }

            return null;
        }

        private byte[] generateKey(KeyDerivationFunc pbkdAlgorithm, String purpose, char[] password)
            throws IOException
        {
            FipsPBKD.DeriverFactory pbeFact = new FipsPBKD.DeriverFactory();

            byte[] encPassword = PasswordConverter.PKCS12.convert(password);
            byte[] differentiator = PasswordConverter.PKCS12.convert(purpose.toCharArray());

            FipsPBKD.Parameters parameters;
            int                 keySizeInBytes;
            if (pbkdAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBKDF2))
            {
                PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbkdAlgorithm.getParameters());

                if (pbkdf2Params.getPrf().getAlgorithm().equals(PKCSObjectIdentifiers.id_hmacWithSHA512))
                {
                    parameters = FipsPBKD.PBKDF2.using(FipsSHS.Algorithm.SHA512_HMAC, Arrays.concatenate(encPassword, differentiator))
                        .withIterationCount(pbkdf2Params.getIterationCount().intValue())
                        .withSalt(pbkdf2Params.getSalt());
                    keySizeInBytes = pbkdf2Params.getKeyLength().intValue();
                }
                else
                {
                    throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD PRF.");
                }
            }
            else
            {
                throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD.");
            }

            PasswordBasedDeriver deriver = pbeFact.createDeriver(parameters);

            return deriver.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, keySizeInBytes);
        }

        private void verifyMac(byte[] content, PbkdMacIntegrityCheck integrityCheck, char[] password)
            throws NoSuchAlgorithmException, IOException
        {
            byte[] check = calculateMac(content, integrityCheck.getMacAlgorithm(), integrityCheck.getPbkdAlgorithm(), password);

            if (!Arrays.constantTimeAreEqual(check, integrityCheck.getMac()))
            {
                throw new IOException("BCFKS KeyStore corrupted: MAC calculation failed.");
            }
        }

        private byte[] calculateMac(byte[] content, AlgorithmIdentifier algorithm, KeyDerivationFunc pbkdAlgorithm, char[] password)
            throws NoSuchAlgorithmException, IOException
        {
            String algorithmId = algorithm.getAlgorithm().getId();

            Mac mac;
            if (fipsProvider != null)
            {
                mac = Mac.getInstance(algorithmId, fipsProvider);
            }
            else
            {
                mac = Mac.getInstance(algorithmId);
            }

            try
            {
                mac.init(new SecretKeySpec(generateKey(pbkdAlgorithm, "INTEGRITY_CHECK", ((password != null) ? password : new char[0])), algorithmId));
            }
            catch (InvalidKeyException e)
            {
                throw new ProvIOException("Cannot set up MAC calculation: " + e.getMessage(), e);
            }

            return mac.doFinal(content);
        }

        @Override
        public void engineStore(OutputStream outputStream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException
        {
            ObjectData[] dataArray = entries.values().toArray(new ObjectData[entries.size()]);

            KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(256 / 8);
            byte[] keyBytes = generateKey(pbkdAlgId, "STORE_ENCRYPTION", ((password != null) ? password : new char[0]));

            ObjectStoreData storeData = new ObjectStoreData(hmacAlgorithm, creationDate, lastModifiedDate, new ObjectDataSequence(dataArray), null);

            FipsAES.AEADOperatorFactory opFact = new FipsAES.AEADOperatorFactory();
            FipsAES.AuthParameters      aeadParams = FipsAES.CCM.withIV(getDefaultSecureRandom());
            OutputAEADEncryptor         encryptor = opFact.createOutputAEADEncryptor(new SymmetricSecretKey(FipsAES.CCM, keyBytes), aeadParams);

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            OutputStream encOut = encryptor.getEncryptingStream(bOut);

            encOut.write(storeData.getEncoded());

            encOut.close();

            PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, new CCMParameters(aeadParams.getIV(), aeadParams.getMACSizeInBits() / 8)));

            EncryptedObjectStoreData encStoreData = new EncryptedObjectStoreData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pbeParams), bOut.toByteArray());

            // update the salt
            PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(hmacPkbdAlgorithm.getParameters());

            byte[] pbkdSalt = new byte[pbkdf2Params.getSalt().length];
            getDefaultSecureRandom().nextBytes(pbkdSalt);

            hmacPkbdAlgorithm = new KeyDerivationFunc(hmacPkbdAlgorithm.getAlgorithm(), new PBKDF2Params(pbkdSalt, pbkdf2Params.getIterationCount().intValue(), pbkdf2Params.getKeyLength().intValue(), pbkdf2Params.getPrf()));

            byte[] mac = calculateMac(encStoreData.getEncoded(), hmacAlgorithm, hmacPkbdAlgorithm, password);

            ObjectStore store = new ObjectStore(encStoreData, new ObjectStoreIntegrityCheck(new PbkdMacIntegrityCheck(hmacAlgorithm, hmacPkbdAlgorithm, mac)));

            outputStream.write(store.getEncoded());

            outputStream.flush();
        }

        @Override
        public void engineLoad(InputStream inputStream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException
        {
            // reset any current values
            entries.clear();
            privateKeyCache.clear();

            lastModifiedDate = creationDate = null;
            hmacAlgorithm = null;

            if (inputStream == null)
            {
                // initialise defaults
                lastModifiedDate = creationDate = new Date();

                hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);
                hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(512 / 8);

                return;
            }

            ASN1InputStream aIn = new ASN1InputStream(inputStream);

            ObjectStore store = ObjectStore.getInstance(aIn.readObject());

            ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();
            if (integrityCheck.getType() == ObjectStoreIntegrityCheck.PBKD_MAC_CHECK)
            {
                PbkdMacIntegrityCheck pbkdMacIntegrityCheck = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

                hmacAlgorithm = pbkdMacIntegrityCheck.getMacAlgorithm();
                hmacPkbdAlgorithm = pbkdMacIntegrityCheck.getPbkdAlgorithm();

                verifyMac(store.getStoreData().toASN1Primitive().getEncoded(), pbkdMacIntegrityCheck, password);
            }
            else
            {
                throw new IOException("BCFKS KeyStore unable to recognize integrity check.");
            }

            ASN1Encodable sData = store.getStoreData();

            ObjectStoreData storeData;
            if (sData instanceof EncryptedObjectStoreData)
            {
                EncryptedObjectStoreData    encryptedStoreData = (EncryptedObjectStoreData)sData;
                AlgorithmIdentifier         protectAlgId = encryptedStoreData.getEncryptionAlgorithm();

                storeData = ObjectStoreData.getInstance(decryptData("STORE_ENCRYPTION", protectAlgId, password, encryptedStoreData.getEncryptedContent().getOctets()));
            }
            else
            {
                storeData = ObjectStoreData.getInstance(sData);
            }


            try
            {
                creationDate = storeData.getCreationDate().getDate();
                lastModifiedDate = storeData.getLastModifiedDate().getDate();
            }
            catch (ParseException e)
            {
                throw new IOException("BCFKS KeyStore unable to parse store data information.");
            }

            if (!storeData.getIntegrityAlgorithm().equals(hmacAlgorithm))
            {
                throw new IOException("BCFKS KeyStore storeData integrity algorithm does not match store integrity algorithm.");
            }

            for (Iterator it = storeData.getObjectDataSequence().iterator(); it.hasNext();)
            {
                ObjectData objData = ObjectData.getInstance(it.next());

                entries.put(objData.getIdentifier(), objData);
            }
        }

        private byte[] decryptData(String purpose, AlgorithmIdentifier protectAlgId, char[] password, byte[] encryptedData)
            throws IOException
        {
            if (!protectAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBES2))
            {
                throw new IOException("BCFKS KeyStore cannot recognize protection algorithm.");
            }

            PBES2Parameters pbes2Parameters = PBES2Parameters.getInstance(protectAlgId.getParameters());
            EncryptionScheme algId = pbes2Parameters.getEncryptionScheme();

            if (!algId.getAlgorithm().equals(NISTObjectIdentifiers.id_aes256_CCM))
            {
                throw new IOException("BCFKS KeyStore cannot recognize protection encryption algorithm.");
            }

            CCMParameters ccmParameters = CCMParameters.getInstance(algId.getParameters());
            FipsAES.AuthParameters      aeadParams = FipsAES.CCM.withIV(ccmParameters.getNonce()).withMACSize(ccmParameters.getIcvLen() * 8);
            FipsAES.AEADOperatorFactory opFact = new FipsAES.AEADOperatorFactory();

            byte[] keyBytes = generateKey(pbes2Parameters.getKeyDerivationFunc(), purpose, ((password != null) ? password : new char[0]));

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            OutputAEADDecryptor decryptor = opFact.createOutputAEADDecryptor(new SymmetricSecretKey(FipsAES.CCM, keyBytes), aeadParams);

            OutputStream dOut = decryptor.getDecryptingStream(bOut);

            dOut.write(encryptedData);

            dOut.close();

            return bOut.toByteArray();
        }

        private KeyDerivationFunc generatePkbdAlgorithmIdentifier(int keySizeInBytes)
        {
            byte[] pbkdSalt = new byte[512 / 8];
            getDefaultSecureRandom().nextBytes(pbkdSalt);
            return new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(pbkdSalt, 1024, keySizeInBytes, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE)));
        }
    }

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.keystore" + ".bcfks.";

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyStore.BCFKS", PREFIX + "BCFKSKeyStore", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BCFIPSKeyStoreSpi(provider);
            }
        });

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("KeyStore.BCFKS-DEF", PREFIX + "BCFKSDefKeyStore", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BCFIPSKeyStoreSpi(null);
                }
            }));
        }
    }
}
