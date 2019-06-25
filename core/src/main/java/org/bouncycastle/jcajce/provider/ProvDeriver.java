package org.bouncycastle.jcajce.provider;

import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.crypto.PasswordBasedDeriver;

interface ProvDeriver
{
    byte[][] getSecretKeyAndIV(PBEKey pbeKey, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits, int ivvSizeInBits);

    byte[] getSecretKey(PBEKey pbeKey, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits);
}
