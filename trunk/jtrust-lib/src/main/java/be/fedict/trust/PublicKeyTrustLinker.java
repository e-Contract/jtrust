/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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

package be.fedict.trust;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * Public key trust linker implementation. Performs simple sanity checks based
 * on the public keys.
 * 
 * @author Frank Cornelis
 */
public class PublicKeyTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory
			.getLog(PublicKeyTrustLinker.class);

	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData, AlgorithmPolicy algorithmPolicy) {
		if (false == childCertificate.getIssuerX500Principal().equals(
				certificate.getSubjectX500Principal())) {
			LOG.debug("child certificate issuer not the same as the issuer certificate subject");
			LOG.debug("child certificate: "
					+ childCertificate.getSubjectX500Principal());
			LOG.debug("certificate: " + certificate.getSubjectX500Principal());
			LOG.debug("child certificate issuer: "
					+ childCertificate.getIssuerX500Principal());
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"child certificate issuer not the same as the issuer certificate subject");
		}
		try {
			childCertificate.verify(certificate.getPublicKey());
		} catch (Exception e) {
			LOG.debug("verification error: " + e.getMessage(), e);
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_SIGNATURE,
					"verification error: " + e.getMessage());
		}

		try {
			algorithmPolicy.checkSignatureAlgorithm(childCertificate
					.getSigAlgOID());
		} catch (SignatureException e) {
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_SIGNATURE,
					"algorithm error: " + e.getMessage());
		}

		if (true == childCertificate.getNotAfter().after(
				certificate.getNotAfter())) {
			LOG.warn("child certificate validity end is after certificate validity end");
			LOG.warn("child certificate validity end: "
					+ childCertificate.getNotAfter());
			LOG.warn("certificate validity end: " + certificate.getNotAfter());
		}
		if (true == childCertificate.getNotBefore().before(
				certificate.getNotBefore())) {
			LOG.warn("child certificate validity begin before certificate validity begin");
			LOG.warn("child certificate validity begin: "
					+ childCertificate.getNotBefore());
			LOG.warn("certificate validity begin: "
					+ certificate.getNotBefore());
		}
		if (true == validationDate.before(childCertificate.getNotBefore())) {
			LOG.debug("certificate is not yet valid");
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"certificate is not yet valid");
		}
		if (true == validationDate.after(childCertificate.getNotAfter())) {
			LOG.debug("certificate already expired");
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"certificate already expired");
		}
		if (-1 == certificate.getBasicConstraints()) {
			LOG.debug("certificate not a CA: "
					+ certificate.getSubjectX500Principal());
			/*
			 * http://www.valicert.com/ Root CA has no CA flag set. Actually
			 * this is in violation with 4.2.1.10 Basic Constraints of RFC2459.
			 */
			try {
				certificate.verify(certificate.getPublicKey());
				LOG.warn("allowing self-signed Root CA without CA flag set");
			} catch (Exception e) {
				return new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_TRUST,
						"certificate not a CA");
			}
		}
		if (0 == certificate.getBasicConstraints()
				&& -1 != childCertificate.getBasicConstraints()) {
			LOG.debug("child should not be a CA");
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"child should not be a CA");
		}

		/*
		 * SKID/AKID sanity check
		 */
		boolean isCa = isCa(certificate);
		boolean isChildCa = isCa(childCertificate);

		byte[] subjectKeyIdentifierData = certificate
				.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
		byte[] authorityKeyIdentifierData = childCertificate
				.getExtensionValue(X509Extensions.AuthorityKeyIdentifier
						.getId());

		if (isCa && null == subjectKeyIdentifierData) {
			LOG.debug("certificate is CA and MUST contain a Subject Key Identifier");
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"certificate is CA and  MUST contain a Subject Key Identifier");
		}

		if (isChildCa && null == authorityKeyIdentifierData
				&& null != subjectKeyIdentifierData) {
			LOG.error("child certificate is CA and MUST contain an Authority Key Identifier");
			//return new TrustLinkerResult(false,
			//		TrustLinkerResultReason.INVALID_TRUST,
			//		"child certificate is CA and MUST contain an Authority Key Identifier");
		}

		if (null != subjectKeyIdentifierData
				&& null != authorityKeyIdentifierData) {

			AuthorityKeyIdentifierStructure authorityKeyIdentifierStructure;
			try {
				authorityKeyIdentifierStructure = new AuthorityKeyIdentifierStructure(
						authorityKeyIdentifierData);
			} catch (IOException e) {
				LOG.debug("Error parsing authority key identifier structure");
				return new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_TRUST,
						"Error parsing authority key identifier structure");
			}
			String akidId = new String(
					Hex.encodeHex(authorityKeyIdentifierStructure
							.getKeyIdentifier()));

			SubjectKeyIdentifierStructure subjectKeyIdentifierStructure;
			try {
				subjectKeyIdentifierStructure = new SubjectKeyIdentifierStructure(
						subjectKeyIdentifierData);
			} catch (IOException e) {
				LOG.debug("Error parsing subject key identifier structure");
				return new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_TRUST,
						"Error parsing subject key identifier structure");
			}
			String skidId = new String(
					Hex.encodeHex(subjectKeyIdentifierStructure
							.getKeyIdentifier()));

			if (!skidId.equals(akidId)) {
				LOG.debug("certificate's subject key identifier does not match child certificate's authority key identifier");
				return new TrustLinkerResult(
						false,
						TrustLinkerResultReason.INVALID_TRUST,
						"certificate's subject key identifier does not match child certificate's authority key identifier");
			}
		}

		/*
		 * We don't check pathLenConstraint since this one is only there to
		 * protect the PKI business.
		 */
		return null;
	}

	private boolean isCa(X509Certificate certificate) {

		byte[] basicConstraintsValue = certificate
				.getExtensionValue(X509Extensions.BasicConstraints.getId());
		if (null == basicConstraintsValue) {
			return false;
		}

		ASN1Encodable basicConstraintsDecoded;
		try {
			basicConstraintsDecoded = X509ExtensionUtil
					.fromExtensionValue(basicConstraintsValue);
		} catch (IOException e) {
			LOG.error("IO error", e);
			return false;
		}
		if (false == basicConstraintsDecoded instanceof ASN1Sequence) {
			LOG.debug("basic constraints extension is not an ASN1 sequence");
			return false;
		}
		ASN1Sequence basicConstraintsSequence = (ASN1Sequence) basicConstraintsDecoded;
		BasicConstraints basicConstraints = new BasicConstraints(
				basicConstraintsSequence);
		return basicConstraints.isCA();
	}
}
