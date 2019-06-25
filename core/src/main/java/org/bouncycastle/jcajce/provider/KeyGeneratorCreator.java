package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;

import org.bouncycastle.crypto.SymmetricKeyGenerator;

interface KeyGeneratorCreator
{
    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random);
}
