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
 * @author fcorneli
 * 
 */
public class PublicKeyTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory
			.getLog(PublicKeyTrustLinker.class);

	public Boolean hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate) {
		if (false == childCertificate.getIssuerX500Principal().equals(
				certificate.getSubjectX500Principal())) {
			LOG
					.debug("child certificate issuer not the same as the issuer certificate subject");
			return false;
		}
		try {
			childCertificate.verify(certificate.getPublicKey());
		} catch (Exception e) {
			LOG.debug("verification error: " + e.getMessage(), e);
			return false;
		}
		if (true == childCertificate.getNotAfter().after(
				certificate.getNotAfter())) {
			LOG
					.debug("child certificate validity end is before certificate validity end");
			return false;
		}
		if (true == childCertificate.getNotBefore().before(
				certificate.getNotBefore())) {
			LOG
					.debug("child certificate validity begin after certificate validity begin");
			LOG.debug("child certificate validity begin: "
					+ childCertificate.getNotBefore());
			LOG.debug("certificate validity begin: "
					+ certificate.getNotBefore());
			return false;
		}
		if (true == validationDate.before(childCertificate.getNotBefore())) {
			LOG.debug("certificate is not yet valid");
			return false;
		}
		if (true == validationDate.after(childCertificate.getNotAfter())) {
			LOG.debug("certificate already expired");
			return false;
		}
		if (-1 == certificate.getBasicConstraints()) {
			LOG.debug("certificate not a CA");
			return false;
		}
		if (0 == certificate.getBasicConstraints()
				&& -1 != childCertificate.getBasicConstraints()) {
			LOG.debug("child should not be a CA");
			return false;
		}
		/*
		 * We don't check pathLenConstraint since this one is only there to
		 * protect the PKI business.
		 */
		return null;
	}
}
