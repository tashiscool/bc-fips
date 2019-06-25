package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayOutputStream;
import java.security.AccessController;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.OperatorUsingSecureRandom;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.SecureHash;

class Utils
{
    static Map<String, DigestAlgorithm> digestNameToAlgMap = new HashMap<String, DigestAlgorithm>();
    static Map<DigestAlgorithm, DigestAlgorithm> hmacToAlgMap = new HashMap<DigestAlgorithm, DigestAlgorithm>();

    static
    {
        digestNameToAlgMap.put("SHA-1", FipsSHS.Algorithm.SHA1);
        digestNameToAlgMap.put("SHA-224", FipsSHS.Algorithm.SHA224);
        digestNameToAlgMap.put("SHA-256", FipsSHS.Algorithm.SHA256);
        digestNameToAlgMap.put("SHA-384", FipsSHS.Algorithm.SHA384);
        digestNameToAlgMap.put("SHA-512", FipsSHS.Algorithm.SHA512);

        hmacToAlgMap.put(FipsSHS.Algorithm.SHA1_HMAC, FipsSHS.Algorithm.SHA1);
        hmacToAlgMap.put(FipsSHS.Algorithm.SHA224_HMAC, FipsSHS.Algorithm.SHA224);
        hmacToAlgMap.put(FipsSHS.Algorithm.SHA256_HMAC, FipsSHS.Algorithm.SHA256);
        hmacToAlgMap.put(FipsSHS.Algorithm.SHA384_HMAC, FipsSHS.Algorithm.SHA384);
        hmacToAlgMap.put(FipsSHS.Algorithm.SHA512_HMAC, FipsSHS.Algorithm.SHA512);
        hmacToAlgMap.put(FipsSHS.Algorithm.SHA512_224_HMAC, FipsSHS.Algorithm.SHA512_224);
        hmacToAlgMap.put(FipsSHS.Algorithm.SHA512_256_HMAC, FipsSHS.Algorithm.SHA512_256);

        hmacToAlgMap.put(SecureHash.Algorithm.MD5_HMAC, SecureHash.Algorithm.MD5);
        hmacToAlgMap.put(SecureHash.Algorithm.GOST3411_HMAC, SecureHash.Algorithm.GOST3411);
        hmacToAlgMap.put(SecureHash.Algorithm.RIPEMD128_HMAC, SecureHash.Algorithm.RIPEMD128);
        hmacToAlgMap.put(SecureHash.Algorithm.RIPEMD160_HMAC, SecureHash.Algorithm.RIPEMD160);
        hmacToAlgMap.put(SecureHash.Algorithm.RIPEMD256_HMAC, SecureHash.Algorithm.RIPEMD256);
        hmacToAlgMap.put(SecureHash.Algorithm.RIPEMD320_HMAC, SecureHash.Algorithm.RIPEMD320);
        hmacToAlgMap.put(SecureHash.Algorithm.WHIRLPOOL_HMAC, SecureHash.Algorithm.WHIRLPOOL);
        hmacToAlgMap.put(SecureHash.Algorithm.TIGER_HMAC, SecureHash.Algorithm.TIGER);
    }

    static boolean isAuthMode(Algorithm algorithm)
    {
        String name = algorithm.getName();

        return name.contains("/CCM") || name.contains("/EAX") || name.contains("/GCM") || name.contains("/CFB8MAC")
            || name.contains("/OCB") || name.contains("/GMAC") || name.contains("/CMAC") || name.contains("/CBCMAC") || name.contains("/MAC");
    }

    static String getBaseName(Algorithm algorithm)
    {
        String name = algorithm.getName();

        int slashIndex = name.indexOf('/');

        if (slashIndex > 0)
        {
            name = name.substring(0, slashIndex);
        }

        if (name.equals("TripleDES")) // translate to JCE convention
        {
            return "DESede";
        }

        return name;
    }

    static boolean isNotNull(ASN1Encodable parameters)
    {
        return parameters != null && !DERNull.INSTANCE.equals(parameters.toASN1Primitive());
    }

    static <T> T  addRandomIfNeeded(T operator, SecureRandom random)
    {
        if (operator instanceof OperatorUsingSecureRandom)
        {
            return (T)((OperatorUsingSecureRandom)operator).withSecureRandom(random);
        }

        return operator;
    }

    static byte[] getKeyEncoding(Key key)
        throws InvalidKeyException
    {
        byte[] keyEnc = key.getEncoded();

        if (keyEnc == null || keyEnc.length == 0)
        {
            throw new InvalidKeyException("no encoding for key");
        }

        return keyEnc;
    }

    static Set<Algorithm> getActiveSet(Algorithm[] algorithms)
    {
        Set<Algorithm> activeSet = new LinkedHashSet<Algorithm>();

        for (Algorithm algorithm : algorithms)
        {
            if (algorithm instanceof FipsAlgorithm)
            {
                activeSet.add(algorithm);
            }
        }

        return activeSet;
    }

    static void clearAndResetByteArrayOutputStream(ByteArrayOutputStream bOut)
    {
        int size = bOut.size();

        bOut.reset();

        for (int i = 0; i != size; i++)
        {
            bOut.write(0);
        }

        bOut.reset();
    }

    static SymmetricKey convertKey(Algorithm algorithm, Key secretKey)
        throws InvalidKeyException
    {
        if (!(secretKey instanceof SecretKey))
        {
             throw new InvalidKeyException("Key needs to be SecretKey.");
        }
        if (secretKey instanceof ProvSecretKeySpec)
        {
            return ((ProvSecretKeySpec)secretKey).getBaseKey();
        }

        return new SymmetricSecretKey(algorithm, secretKey.getEncoded());
    }

    static DigestAlgorithm getUnderlyingDigestAlgorithm(Algorithm algorithm)
    {
        DigestAlgorithm digest = hmacToAlgMap.get(algorithm);

        if (digest != null)
        {
            return digest;
        }

        throw new IllegalStateException("HMAC algorithm not recognized: " + algorithm.getName());
    }

    static boolean keyNotLength(final SymmetricKey key, int keySizeInBits)
    {
        byte[] keyBytes = AccessController.doPrivileged(new PrivilegedAction<byte[]>()
                {
                    public byte[] run()
                    {
                        return key.getKeyBytes();
                    }
                });

        return keyBytes.length != ((keySizeInBits + 7) / 8);
    }
}
