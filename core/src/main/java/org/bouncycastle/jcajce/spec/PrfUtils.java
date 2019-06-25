package org.bouncycastle.jcajce.spec;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.SecureHash;

class PrfUtils
{
    private static Map<Algorithm, AlgorithmIdentifier> hmacAlgIds = new HashMap<Algorithm, AlgorithmIdentifier>();
    private static Map<Algorithm, ASN1ObjectIdentifier> digestOIDs = new HashMap<Algorithm, ASN1ObjectIdentifier>();

    static
    {
        hmacAlgIds.put(FipsSHS.Algorithm.SHA1_HMAC, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE));
        hmacAlgIds.put(FipsSHS.Algorithm.SHA224_HMAC, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA224, DERNull.INSTANCE));
        hmacAlgIds.put(FipsSHS.Algorithm.SHA256_HMAC, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));
        hmacAlgIds.put(FipsSHS.Algorithm.SHA384_HMAC, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA384, DERNull.INSTANCE));
        hmacAlgIds.put(FipsSHS.Algorithm.SHA512_HMAC, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE));
        hmacAlgIds.put(SecureHash.Algorithm.GOST3411_HMAC, new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411Hmac, DERNull.INSTANCE));
        hmacAlgIds.put(SecureHash.Algorithm.RIPEMD160_HMAC, new AlgorithmIdentifier(IANAObjectIdentifiers.hmacRIPEMD160, DERNull.INSTANCE));
        hmacAlgIds.put(SecureHash.Algorithm.TIGER_HMAC, new AlgorithmIdentifier(IANAObjectIdentifiers.hmacTIGER, DERNull.INSTANCE));

        digestOIDs.put(FipsSHS.Algorithm.SHA1, OIWObjectIdentifiers.idSHA1);
        digestOIDs.put(FipsSHS.Algorithm.SHA224, NISTObjectIdentifiers.id_sha224);
        digestOIDs.put(FipsSHS.Algorithm.SHA256, NISTObjectIdentifiers.id_sha256);
        digestOIDs.put(FipsSHS.Algorithm.SHA384, NISTObjectIdentifiers.id_sha384);
        digestOIDs.put(FipsSHS.Algorithm.SHA512, NISTObjectIdentifiers.id_sha512);
        digestOIDs.put(SecureHash.Algorithm.RIPEMD160, TeleTrusTObjectIdentifiers.ripemd160);
        digestOIDs.put(SecureHash.Algorithm.RIPEMD256, TeleTrusTObjectIdentifiers.ripemd256);
        digestOIDs.put(SecureHash.Algorithm.WHIRLPOOL, ISOIECObjectIdentifiers.whirlpool);
    }

    static AlgorithmIdentifier getAlgorithmIdentifier(Algorithm prfAlg)
    {
        AlgorithmIdentifier algId = hmacAlgIds.get(prfAlg);

        if (algId == null)
        {
            throw new IllegalArgumentException("Unknown PRF requested: " + prfAlg.getName());
        }

        return algId;
    }

    public static ASN1ObjectIdentifier getObjectIdentifier(Algorithm digestAlgorithm)
    {
        ASN1ObjectIdentifier oid = digestOIDs.get(digestAlgorithm);

        if (oid == null)
        {
            throw new IllegalArgumentException("Unrecognized digest requested: " + digestAlgorithm.getName());
        }

        return oid;
    }
}
