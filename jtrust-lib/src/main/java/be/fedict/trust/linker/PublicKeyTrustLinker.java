/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014-2023 e-Contract.be BV.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.fedict.trust.linker;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;

/**
 * Public key trust linker implementation. Performs simple sanity checks based
 * on the public keys.
 * 
 * @author Frank Cornelis
 */
public class PublicKeyTrustLinker implements TrustLinker {

	private static final Logger LOGGER = LoggerFactory.getLogger(PublicKeyTrustLinker.class);

	private final boolean expiredMode;

	public PublicKeyTrustLinker() {
		this(false);
	}

	public PublicKeyTrustLinker(boolean expiredMode) {
		this.expiredMode = expiredMode;
	}

	@Override
	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate, X509Certificate certificate,
			Date validationDate, RevocationData revocationData, AlgorithmPolicy algorithmPolicy)
			throws TrustLinkerResultException, Exception {
		if (false == childCertificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
			LOGGER.warn("child certificate issuer not the same as the issuer certificate subject");
			LOGGER.warn("child certificate: {}", childCertificate.getSubjectX500Principal());
			LOGGER.warn("certificate: {}", certificate.getSubjectX500Principal());
			LOGGER.warn("child certificate issuer: {}", childCertificate.getIssuerX500Principal());
			throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST,
					"child certificate issuer not the same as the issuer certificate subject");
		}
		try {
			childCertificate.verify(certificate.getPublicKey());
		} catch (Exception e) {
			LOGGER.debug("verification error: " + e.getMessage(), e);
			throw new TrustLinkerResultException(TrustLinkerResultReason.INVALID_SIGNATURE,
					"verification error: " + e.getMessage());
		}

		algorithmPolicy.checkSignatureAlgorithm(childCertificate.getSigAlgOID(), validationDate);

		if (true == childCertificate.getNotAfter().after(certificate.getNotAfter())) {
			LOGGER.warn("child certificate validity end is after issuing certificate validity end");
			LOGGER.warn("child certificate validity end: {}", childCertificate.getNotAfter());
			LOGGER.warn("issuing certificate validity end: {}", certificate.getNotAfter());
		}
		if (true == childCertificate.getNotBefore().before(certificate.getNotBefore())) {
			LOGGER.warn("child certificate validity begin before issuing certificate validity begin");
			LOGGER.warn("child certificate validity begin: {}", childCertificate.getNotBefore());
			LOGGER.warn("issuing certificate validity begin: {}", certificate.getNotBefore());
		}
		if (true == validationDate.before(childCertificate.getNotBefore())) {
			LOGGER.debug("certificate is not yet valid");
			LOGGER.debug("validation date: {}", validationDate);
			LOGGER.debug("not before: {}", childCertificate.getNotBefore());
			throw new TrustLinkerResultException(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"certificate is not yet valid");
		}
		if (true == validationDate.after(childCertificate.getNotAfter())) {
			LOGGER.debug("certificate already expired");
			LOGGER.debug("validation date: {}", validationDate);
			LOGGER.debug("not after: {}", childCertificate.getNotAfter());
			if (!this.expiredMode) {
				throw new TrustLinkerResultException(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
						"certificate already expired");
			} else {
				LOGGER.debug("running in expired mode");
			}
		}
		if (-1 == certificate.getBasicConstraints()) {
			LOGGER.warn("certificate not a CA: {}", certificate.getSubjectX500Principal());
			/*
			 * http://www.valicert.com/ Root CA has no CA flag set. Actually this is in
			 * violation with 4.2.1.10 Basic Constraints of RFC2459.
			 */
			try {
				certificate.verify(certificate.getPublicKey());
				LOGGER.warn("allowing self-signed Root CA without CA flag set");
			} catch (Exception e) {
				throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST, "certificate not a CA");
			}
		}
		if (0 == certificate.getBasicConstraints() && -1 != childCertificate.getBasicConstraints()) {
			LOGGER.warn("child should not be a CA: " + childCertificate.getSubjectX500Principal());
			throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST, "child should not be a CA");
		}

		/*
		 * SKID/AKID sanity check
		 */
		boolean isCa = isCa(certificate);
		boolean isChildCa = isCa(childCertificate);

		byte[] subjectKeyIdentifierData = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
		byte[] authorityKeyIdentifierData = childCertificate
				.getExtensionValue(Extension.authorityKeyIdentifier.getId());

		if (isCa && null == subjectKeyIdentifierData) {
			LOGGER.error("certificate is CA and MUST contain a Subject Key Identifier");
			throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST,
					"certificate is CA and  MUST contain a Subject Key Identifier");
		}

		if (isChildCa && null == authorityKeyIdentifierData && null != subjectKeyIdentifierData) {
			LOGGER.error("child certificate is CA and MUST contain an Authority Key Identifier");
			// return new TrustLinkerResult(false,
			// TrustLinkerResultReason.INVALID_TRUST,
			// "child certificate is CA and MUST contain an Authority Key Identifier");
		}

		if (null != subjectKeyIdentifierData && null != authorityKeyIdentifierData) {
			AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier
					.getInstance(JcaX509ExtensionUtils.parseExtensionValue(authorityKeyIdentifierData));
			SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier
					.getInstance(JcaX509ExtensionUtils.parseExtensionValue(subjectKeyIdentifierData));
			if (!Arrays.equals(authorityKeyIdentifier.getKeyIdentifier(), subjectKeyIdentifier.getKeyIdentifier())) {
				LOGGER.error(
						"certificate's subject key identifier does not match child certificate's authority key identifier");
				throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST,
						"certificate's subject key identifier does not match child certificate's authority key identifier");
			}
		}

		/*
		 * We don't check pathLenConstraint since this one is only there to protect the
		 * PKI business.
		 */
		/*
		 * Keep in mind that this trust linker can never return TRUSTED.
		 */
		return TrustLinkerResult.UNDECIDED;
	}

	private boolean isCa(X509Certificate certificate) {
		byte[] basicConstraintsValue = certificate.getExtensionValue(Extension.basicConstraints.getId());
		if (null == basicConstraintsValue) {
			return false;
		}

		ASN1Encodable basicConstraintsDecoded;
		try {
			basicConstraintsDecoded = JcaX509ExtensionUtils.parseExtensionValue(basicConstraintsValue);
		} catch (IOException e) {
			LOGGER.error("IO error", e);
			return false;
		}
		if (false == basicConstraintsDecoded instanceof ASN1Sequence) {
			LOGGER.debug("basic constraints extension is not an ASN1 sequence");
			return false;
		}
		ASN1Sequence basicConstraintsSequence = (ASN1Sequence) basicConstraintsDecoded;
		BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsSequence);
		return basicConstraints.isCA();
	}
}
