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

import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Off line CRL repository. This implementation receives a list of
 * {@link X509CRL} objects.
 * 
 * @author wvdhaute
 */
public class OfflineCrlRepository implements CrlRepository {

	private static final Log LOG = LogFactory
			.getLog(OfflineCrlRepository.class);

	private final List<X509CRL> crls;

	/**
	 * Main constructor
	 * 
	 * @param crls
	 *            the list of {@link X509CRL} objects that can be queried.
	 */
	public OfflineCrlRepository(List<X509CRL> crls) {

		this.crls = crls;
	}

	/**
	 * {@inheritDoc}
	 */
	public X509CRL findCrl(URI crlUri, X509Certificate issuerCertificate,
			Date validationDate) {

		for (X509CRL crl : this.crls) {
			if (crl.getIssuerX500Principal().equals(
					issuerCertificate.getSubjectX500Principal())) {
				LOG.debug("CRL found for issuer "
						+ issuerCertificate.getSubjectX500Principal()
								.toString());
				return crl;
			}
		}

		LOG.debug("CRL not found for issuer "
				+ issuerCertificate.getSubjectX500Principal().toString());
		return null;
	}
}
