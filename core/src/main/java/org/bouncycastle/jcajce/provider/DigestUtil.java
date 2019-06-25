package org.bouncycastle.jcajce.provider;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.util.Strings;

class DigestUtil
{
    private static Map<String, ASN1ObjectIdentifier> oids = new HashMap<String, ASN1ObjectIdentifier>();
    private static Map<String, DigestAlgorithm> algorithms = new HashMap<String, DigestAlgorithm>();

    static
    {
        algorithms.put("MD5", SecureHash.Algorithm.MD5);
        algorithms.put(PKCSObjectIdentifiers.md5.getId(), SecureHash.Algorithm.MD5);
        
        algorithms.put("SHA1", FipsSHS.Algorithm.SHA1);
        algorithms.put("SHA-1", FipsSHS.Algorithm.SHA1);
        algorithms.put(OIWObjectIdentifiers.idSHA1.getId(), FipsSHS.Algorithm.SHA1);
        
        algorithms.put("SHA224", FipsSHS.Algorithm.SHA224);
        algorithms.put("SHA-224", FipsSHS.Algorithm.SHA224);
        algorithms.put(NISTObjectIdentifiers.id_sha224.getId(), FipsSHS.Algorithm.SHA224);
        
        algorithms.put("SHA256", FipsSHS.Algorithm.SHA256);
        algorithms.put("SHA-256", FipsSHS.Algorithm.SHA256);
        algorithms.put(NISTObjectIdentifiers.id_sha256.getId(), FipsSHS.Algorithm.SHA256);
        
        algorithms.put("SHA384", FipsSHS.Algorithm.SHA384);
        algorithms.put("SHA-384", FipsSHS.Algorithm.SHA384);
        algorithms.put(NISTObjectIdentifiers.id_sha384.getId(), FipsSHS.Algorithm.SHA384);
        
        algorithms.put("SHA512", FipsSHS.Algorithm.SHA512);
        algorithms.put("SHA-512", FipsSHS.Algorithm.SHA512);
        algorithms.put(NISTObjectIdentifiers.id_sha512.getId(), FipsSHS.Algorithm.SHA512);

        algorithms.put("SHA512(224)", FipsSHS.Algorithm.SHA512_224);
        algorithms.put("SHA-512(224)", FipsSHS.Algorithm.SHA512_224);
        algorithms.put(NISTObjectIdentifiers.id_sha512_224.getId(), FipsSHS.Algorithm.SHA512_224);

        algorithms.put("SHA512(256)", FipsSHS.Algorithm.SHA512_256);
        algorithms.put("SHA-512(256)", FipsSHS.Algorithm.SHA512_256);
        algorithms.put(NISTObjectIdentifiers.id_sha512_256.getId(), FipsSHS.Algorithm.SHA512_256);

        algorithms.put("RIPEMD128", SecureHash.Algorithm.RIPEMD128);
        algorithms.put("RIPEMD-128", SecureHash.Algorithm.RIPEMD128);
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), SecureHash.Algorithm.RIPEMD128);
        algorithms.put(ISOIECObjectIdentifiers.ripemd128.getId(), SecureHash.Algorithm.RIPEMD128);
        
        algorithms.put("RIPEMD160", SecureHash.Algorithm.RIPEMD160);
        algorithms.put("RIPEMD-160", SecureHash.Algorithm.RIPEMD160);
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), SecureHash.Algorithm.RIPEMD160);
        algorithms.put(ISOIECObjectIdentifiers.ripemd160.getId(), SecureHash.Algorithm.RIPEMD160);
        
        algorithms.put("RIPEMD256", SecureHash.Algorithm.RIPEMD256);
        algorithms.put("RIPEMD-256", SecureHash.Algorithm.RIPEMD256);
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), SecureHash.Algorithm.RIPEMD256);

        algorithms.put("TIGER", SecureHash.Algorithm.TIGER);
        algorithms.put(GNUObjectIdentifiers.Tiger_192.getId(), SecureHash.Algorithm.TIGER);

        algorithms.put("WHIRLPOOL", SecureHash.Algorithm.WHIRLPOOL);
        algorithms.put(ISOIECObjectIdentifiers.whirlpool.getId(), SecureHash.Algorithm.WHIRLPOOL);

        oids.put("MD5", PKCSObjectIdentifiers.md5);
        oids.put(PKCSObjectIdentifiers.md5.getId(), PKCSObjectIdentifiers.md5);
        
        oids.put("SHA1", OIWObjectIdentifiers.idSHA1);
        oids.put("SHA-1", OIWObjectIdentifiers.idSHA1);
        oids.put(OIWObjectIdentifiers.idSHA1.getId(), OIWObjectIdentifiers.idSHA1);
        
        oids.put("SHA224", NISTObjectIdentifiers.id_sha224);
        oids.put("SHA-224", NISTObjectIdentifiers.id_sha224);
        oids.put(NISTObjectIdentifiers.id_sha224.getId(), NISTObjectIdentifiers.id_sha224);
        
        oids.put("SHA256", NISTObjectIdentifiers.id_sha256);
        oids.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        oids.put(NISTObjectIdentifiers.id_sha256.getId(), NISTObjectIdentifiers.id_sha256);
        
        oids.put("SHA384", NISTObjectIdentifiers.id_sha384);
        oids.put("SHA-384", NISTObjectIdentifiers.id_sha384);
        oids.put(NISTObjectIdentifiers.id_sha384.getId(), NISTObjectIdentifiers.id_sha384);
        
        oids.put("SHA512", NISTObjectIdentifiers.id_sha512);
        oids.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        oids.put(NISTObjectIdentifiers.id_sha512.getId(), NISTObjectIdentifiers.id_sha512); 

        oids.put("SHA512(224)", NISTObjectIdentifiers.id_sha512_224);
        oids.put("SHA-512(224)", NISTObjectIdentifiers.id_sha512_224);
        oids.put("SHA512/224", NISTObjectIdentifiers.id_sha512_224);
        oids.put("SHA-512/224", NISTObjectIdentifiers.id_sha512_224);
        oids.put(NISTObjectIdentifiers.id_sha512_224.getId(), NISTObjectIdentifiers.id_sha512_224);

        oids.put("SHA512(256)", NISTObjectIdentifiers.id_sha512_256);
        oids.put("SHA-512(256)", NISTObjectIdentifiers.id_sha512_256);
        oids.put("SHA512/256", NISTObjectIdentifiers.id_sha512_256);
        oids.put("SHA-512/256", NISTObjectIdentifiers.id_sha512_256);
        oids.put(NISTObjectIdentifiers.id_sha512_256.getId(), NISTObjectIdentifiers.id_sha512_256);

        oids.put("RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128);
        oids.put("RIPEMD-128", TeleTrusTObjectIdentifiers.ripemd128);
        oids.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), TeleTrusTObjectIdentifiers.ripemd128);
        oids.put(ISOIECObjectIdentifiers.ripemd128.getId(), TeleTrusTObjectIdentifiers.ripemd128); 
        
        oids.put("RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160);
        oids.put("RIPEMD-160", TeleTrusTObjectIdentifiers.ripemd160);
        oids.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), TeleTrusTObjectIdentifiers.ripemd160);
        oids.put(ISOIECObjectIdentifiers.ripemd160.getId(), TeleTrusTObjectIdentifiers.ripemd160);

        oids.put("RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);
        oids.put("RIPEMD-256", TeleTrusTObjectIdentifiers.ripemd256);
        oids.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), TeleTrusTObjectIdentifiers.ripemd256);

        oids.put("TIGER", GNUObjectIdentifiers.Tiger_192);
        oids.put(GNUObjectIdentifiers.Tiger_192.getId(), GNUObjectIdentifiers.Tiger_192);

        oids.put("WHIRLPOOL", ISOIECObjectIdentifiers.whirlpool);
        oids.put(ISOIECObjectIdentifiers.whirlpool.getId(), ISOIECObjectIdentifiers.whirlpool);
    }

    public static boolean isSameDigest(
        String digest1,
        String digest2)
    {
        Algorithm alg1 = algorithms.get(digest1);
        Algorithm alg2 = algorithms.get(digest2);

        return alg1 != null && alg1.equals(alg2);
    }
    
    public static ASN1ObjectIdentifier getOID(
        String digestName)
    {
        return oids.get(digestName);
    }

    public static DigestAlgorithm getDigestID(String digestAlgorithm)
    {
        return algorithms.get(Strings.toUpperCase(digestAlgorithm));
    }
}
