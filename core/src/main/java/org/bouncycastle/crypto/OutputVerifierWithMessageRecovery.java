package org.bouncycastle.crypto;

/**
 * Interface for an output signer that also supports message recovery from the signature.
 *
 * @param <T> the parameters type for the signer.
 */
public interface OutputVerifierWithMessageRecovery<T extends Parameters>
    extends OutputVerifier<T>
{
    /**
     * Return the recovered message details found in the signature.
     *
     * @return recovered message details.
     */
    RecoveredMessage getRecoveredMessage();

    /**
     * Update the verifier with the recovered message data found in the signature.
     *
     * @param signature the signature we are in the process of verifying.
     * @throws InvalidSignatureException if the signature cannot be processed.
     */
    void updateWithRecoveredMessage(byte[] signature)
        throws InvalidSignatureException;
}
