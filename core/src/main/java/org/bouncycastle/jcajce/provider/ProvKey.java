package org.bouncycastle.jcajce.provider;

import org.bouncycastle.crypto.Key;

interface ProvKey<T extends Key>
{
    T getBaseKey();
}
