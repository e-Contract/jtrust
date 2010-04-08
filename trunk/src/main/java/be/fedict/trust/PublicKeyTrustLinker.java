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

import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Public key trust linker implementation. Performs simple sanity checks based
 * on the public keys.
 * 
 * @author Frank Cornelis
 * 
 */
public class PublicKeyTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory
			.getLog(PublicKeyTrustLinker.class);

	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData) {
		if (false == childCertificate.getIssuerX500Principal().equals(
				certificate.getSubjectX500Principal())) {
			LOG
					.debug("child certificate issuer not the same as the issuer certificate subject");
			LOG.debug("child certificate: "
					+ childCertificate.getSubjectX500Principal());
			LOG.debug("certificate: " + certificate.getSubjectX500Principal());
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
		if (true == childCertificate.getNotAfter().after(
				certificate.getNotAfter())) {
			LOG
					.debug("child certificate validity end is after certificate validity end");
			LOG.debug("child certificate validity end: "
					+ childCertificate.getNotAfter());
			LOG.debug("certificate validity end: " + certificate.getNotAfter());
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"child certificate validity end is after certificate validity end");
		}
		if (true == childCertificate.getNotBefore().before(
				certificate.getNotBefore())) {
			LOG
					.debug("child certificate validity begin before certificate validity begin");
			LOG.debug("child certificate validity begin: "
					+ childCertificate.getNotBefore());
			LOG.debug("certificate validity begin: "
					+ certificate.getNotBefore());
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"child certificate validity begin before certificate validity begin");
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
			LOG.debug("certificate not a CA");
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"certificate not a CA");
		}
		if (0 == certificate.getBasicConstraints()
				&& -1 != childCertificate.getBasicConstraints()) {
			LOG.debug("child should not be a CA");
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"child should not be a CA");
		}
		/*
		 * We don't check pathLenConstraint since this one is only there to
		 * protect the PKI business.
		 */
		return null;
	}
}
