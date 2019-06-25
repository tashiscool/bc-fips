package org.bouncycastle.jcajce.provider;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Integers;

class KeyIvSizeProvider
{
    private final Map KEY_SIZES;

    KeyIvSizeProvider()
    {
        Map<String, Integer> keySizes = new HashMap<String, Integer>();

        keySizes.put(MiscObjectIdentifiers.cast5CBC.getId(), Integers.valueOf(16));

        keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), Integers.valueOf(24));
        keySizes.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), Integers.valueOf(24));
        keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), Integers.valueOf(24));

        keySizes.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), Integers.valueOf(16));
        keySizes.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), Integers.valueOf(24));
        keySizes.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), Integers.valueOf(32));
        keySizes.put(NISTObjectIdentifiers.id_aes128_GCM.getId(), Integers.valueOf(16));
        keySizes.put(NISTObjectIdentifiers.id_aes192_GCM.getId(), Integers.valueOf(24));
        keySizes.put(NISTObjectIdentifiers.id_aes256_GCM.getId(), Integers.valueOf(32));
        keySizes.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), Integers.valueOf(16));
        keySizes.put(NISTObjectIdentifiers.id_aes192_CCM.getId(), Integers.valueOf(24));
        keySizes.put(NISTObjectIdentifiers.id_aes256_CCM.getId(), Integers.valueOf(32));
        keySizes.put(NISTObjectIdentifiers.id_aes128_CFB.getId(), Integers.valueOf(16));
        keySizes.put(NISTObjectIdentifiers.id_aes192_CFB.getId(), Integers.valueOf(24));
        keySizes.put(NISTObjectIdentifiers.id_aes256_CFB.getId(), Integers.valueOf(32));
        keySizes.put(NISTObjectIdentifiers.id_aes128_OFB.getId(), Integers.valueOf(16));
        keySizes.put(NISTObjectIdentifiers.id_aes192_OFB.getId(), Integers.valueOf(24));
        keySizes.put(NISTObjectIdentifiers.id_aes256_OFB.getId(), Integers.valueOf(32));
        keySizes.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), Integers.valueOf(16));
        keySizes.put(NISTObjectIdentifiers.id_aes192_wrap.getId(), Integers.valueOf(24));
        keySizes.put(NISTObjectIdentifiers.id_aes256_wrap.getId(), Integers.valueOf(32));

        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), Integers.valueOf(20));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA224.getId(), Integers.valueOf(28));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), Integers.valueOf(32));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), Integers.valueOf(48));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), Integers.valueOf(64));

        keySizes.put(NTTObjectIdentifiers.id_camellia128_cbc.getId(), Integers.valueOf(16));
        keySizes.put(NTTObjectIdentifiers.id_camellia192_cbc.getId(), Integers.valueOf(24));
        keySizes.put(NTTObjectIdentifiers.id_camellia256_cbc.getId(), Integers.valueOf(32));
        keySizes.put(NTTObjectIdentifiers.id_camellia128_wrap.getId(), Integers.valueOf(16));
        keySizes.put(NTTObjectIdentifiers.id_camellia192_wrap.getId(), Integers.valueOf(24));
        keySizes.put(NTTObjectIdentifiers.id_camellia256_wrap.getId(), Integers.valueOf(32));

        keySizes.put(KISAObjectIdentifiers.id_seedCBC.getId(), Integers.valueOf(16));
        keySizes.put(KISAObjectIdentifiers.id_seedMAC.getId(), Integers.valueOf(16));

        keySizes.put(OIWObjectIdentifiers.desCBC.getId(), Integers.valueOf(8));

        keySizes.put(CryptoProObjectIdentifiers.gostR28147_gcfb.getId(), Integers.valueOf(32));
        keySizes.put(CryptoProObjectIdentifiers.gostR3411Hmac.getId(), Integers.valueOf(32));

        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC.getId(), Integers.valueOf(16));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId(), Integers.valueOf(24));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC.getId(), Integers.valueOf(16));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4.getId(), Integers.valueOf(16));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC.getId(), Integers.valueOf(5));

        KEY_SIZES = Collections.unmodifiableMap(keySizes);
    }

    public int getKeySize(String algorithm)
    {
        Integer keySize = (Integer)KEY_SIZES.get(algorithm);

        if (keySize != null)
        {
            return keySize.intValue();
        }

        return -1;
    }

    public int getKeySize(AlgorithmIdentifier algorithmIdentifier)
    {
        Integer keySize = (Integer)KEY_SIZES.get(algorithmIdentifier.getAlgorithm().getId());

        if (keySize != null)
        {
            return keySize.intValue();
        }

        return -1;
    }
}
