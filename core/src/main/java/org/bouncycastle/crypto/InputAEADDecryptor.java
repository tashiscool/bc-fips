package org.bouncycastle.crypto;

/**
 * Base interface for an input consuming AEAD Decryptor supporting associated text.
 *
 * @param <T> the parameters type for the decryptor.
 */
public interface InputAEADDecryptor<T extends Parameters>
    extends InputDecryptor<T>, AADProcessor
{
}
