package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureScheme;

/**
 * Interface providing the functional representation of a single X.509 certificate.
 */
public interface TlsCertificate
{
    /**
     * Return an encryptor based on the public key in this certificate.
     *
     * @param tlsCertificateRole
     *            {@link TlsCertificateRole}
     * @return a TlsEncryptor based on this certificate's public key.
     */
    TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException;

    /**
     * Return an encryptor based on the public key in this certificate,
     * encryption algorithm and cipher parameters.
     *
     * @param tlsCertificateRole
     *            {@link TlsCertificateRole}
     * @param encryptionAlgorithm
     *            {@link org.bouncycastle.tls.EncryptionAlgorithm}
     * @param cipherParams cipher parameters
     *            {@link AlgorithmParameterSpec}
     * @return a TlsEncryptor based on this certificate's public key.
     */
    TlsEncryptor createEncryptor(int tlsCertificateRole, int encryptionAlgorithm,
        AlgorithmParameterSpec cipherParams) throws IOException;

    /**
     * @param signatureAlgorithm
     *            {@link SignatureAlgorithm}
     */
    TlsVerifier createVerifier(short signatureAlgorithm) throws IOException;

    /**
     * @param signatureScheme
     *            {@link SignatureScheme}
     */
    Tls13Verifier createVerifier(int signatureScheme) throws IOException;

    byte[] getEncoded() throws IOException;

    byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException;

    BigInteger getSerialNumber();

    /**
     * @return the OID of this certificate's 'signatureAlgorithm', as a String.
     */
    String getSigAlgOID();

    ASN1Encodable getSigAlgParams() throws IOException;

    /**
     * @return {@link SignatureAlgorithm}
     */
    short getLegacySignatureAlgorithm() throws IOException;

    /**
     * @param signatureAlgorithm {@link SignatureAlgorithm}
     * @return true if (and only if) this certificate can be used to verify the given signature algorithm. 
     */
    boolean supportsSignatureAlgorithm(short signatureAlgorithm) throws IOException;

    boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) throws IOException;

    /**
     * @param tlsCertificateRole
     *            {@link TlsCertificateRole}
     */
    TlsCertificate checkUsageInRole(int tlsCertificateRole) throws IOException;
}
