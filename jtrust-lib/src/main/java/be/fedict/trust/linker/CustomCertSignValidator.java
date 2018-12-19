package be.fedict.trust.linker;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Custom validator to validate the signature on a certificate.
 */
public class CustomCertSignValidator {

    private static final Log LOG = LogFactory.getLog(CustomCertSignValidator.class);

    /**
     * Verifies that the public key of the given self-signed Root CA is used to sign itself.
     *
     * Try to verify the signature with the standard algorithm.
     * If that doesn't succeed, the signature is verified with PKCS1 padding.
     *
     * @param certificate
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public static void verify(X509Certificate certificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException {
        verify(certificate, certificate);
    }

    /**
     * Verifies that the public key in the first certificate is used to encrypt the second certificate.
     *
     * Try to verify the signature with the standard algorithm.
     * If that doesn't succeed, the signature is verified with PKCS1 padding.
     * If a SignatureException occurs with the message describing an issue with the signature length,
     * we move over the verifyWithPKCS1Padding.
     *
     * http://www.bouncycastle.org/wiki/display/JA1/Frequently+Asked+Questions#FrequentlyAskedQuestions-4.WhenIencryptsomethingwithRSAIamlosingleadingzerobytesoffmydata,whyareyouguysshippingsuchabrokenimplementation
     *
     * @param childCertificate
     * @param certificate
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CertificateEncodingException
     */
    public static void verify(X509Certificate childCertificate, X509Certificate certificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException {

        if (childCertificate == null) {
            throw new NullPointerException("The childCertificate can not be null");
        }

        if (certificate == null) {
            throw new NullPointerException("The certificate can not be null");
        }

        try {
            childCertificate.verify(certificate.getPublicKey());
        } catch (SignatureException e) {
            if (e.getMessage().contains("Signature length not correct")) {
                verifyWithPKCS1Padding(childCertificate, certificate);
            }
        }

    }

    public static void verifyWithPKCS1Padding(X509Certificate childCertificate, X509Certificate certificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException {
        LOG.debug("Signature lenth is not correct for childCertificate (" + childCertificate.getSubjectDN().getName() + "), and certificate (" + certificate.getSubjectDN().getName() + ").");
        String certificateSignatureAlgorithm = childCertificate.getSigAlgName();
        if (!certificateSignatureAlgorithm.contains("Encryption")) {
            certificateSignatureAlgorithm = certificateSignatureAlgorithm + "Encryption";
        }

        final Signature signature = Signature.getInstance(certificateSignatureAlgorithm);
        LOG.debug("Using " + signature.getAlgorithm() + " algorithm for signature verification.");
        signature.initVerify(certificate.getPublicKey());
        final byte[] encodedInfo = childCertificate.getTBSCertificate();
        signature.update(encodedInfo, 0, encodedInfo.length);
        final boolean verificationResult = signature.verify(childCertificate.getSignature());

        if (!verificationResult) {
            throw new SignatureException("Signature does not match.");
        }
    }

}
