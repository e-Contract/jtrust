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

package be.fedict.trust.crl;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Off line CRL repository. This implementation receives a list of
 * {@link X509CRL} objects. If multiple CRLs match, one within the given
 * validation date is returned. This behavior is important for the historical
 * validation of certain types of signatures.
 * 
 * @author Frank Cornelis
 */
public class OfflineCrlRepository implements CrlRepository {

	private static final Log LOG = LogFactory
			.getLog(OfflineCrlRepository.class);

	private final List<X509CRL> crls;

	/**
	 * Main constructor
	 * 
	 * @param encodedCrls
	 *            the list of encoded CRL's that can be queried.
	 * @throws NoSuchProviderException
	 * @throws CertificateException
	 * @throws CRLException
	 */
	public OfflineCrlRepository(List<byte[]> encodedCrls)
			throws CertificateException, NoSuchProviderException, CRLException {

		CertificateFactory certificateFactory = CertificateFactory.getInstance(
				"X.509", "BC");
		this.crls = new LinkedList<X509CRL>();
		for (byte[] encodedCrl : encodedCrls) {
			ByteArrayInputStream bais = new ByteArrayInputStream(encodedCrl);
			this.crls.add((X509CRL) certificateFactory.generateCRL(bais));
		}
	}

	public X509CRL findCrl(URI crlUri, X509Certificate issuerCertificate,
			Date validationDate) {

		List<X509CRL> matchingCrls = new LinkedList<X509CRL>();
		for (X509CRL crl : this.crls) {
			if (crl.getIssuerX500Principal().equals(
					issuerCertificate.getSubjectX500Principal())) {
				LOG.debug("CRL found for issuer "
						+ issuerCertificate.getSubjectX500Principal()
								.toString());
				matchingCrls.add(crl);
			}
		}

		if (matchingCrls.isEmpty()) {
			LOG.debug("CRL not found for issuer "
					+ issuerCertificate.getSubjectX500Principal().toString());
			return null;
		}

		if (matchingCrls.size() == 1) {
			return matchingCrls.get(0);
		}

		LOG.debug("multiple matching CRLs found");
		for (X509CRL crl : matchingCrls) {
			if (isCrlInValidationDate(crl, validationDate)) {
				return crl;
			}
		}
		return null;
	}

	private boolean isCrlInValidationDate(X509CRL crl, Date validationDate) {
		Date thisUpdate = crl.getThisUpdate();
		LOG.debug("validation date: " + validationDate);
		LOG.debug("CRL this update: " + thisUpdate);
		if (thisUpdate.after(validationDate)) {
			LOG.warn("CRL too young");
			return false;
		}
		LOG.debug("CRL next update: " + crl.getNextUpdate());
		if (validationDate.after(crl.getNextUpdate())) {
			LOG.debug("CRL too old");
			return false;
		}
		return true;
	}
}
