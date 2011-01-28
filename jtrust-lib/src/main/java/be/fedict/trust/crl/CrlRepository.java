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

/**
 * Interface for CRL repository components.
 * 
 * @author Frank Cornelis
 * 
 */
public interface CrlRepository {

	/**
	 * Finds the request CRL.
	 * 
	 * @param crlUri
	 *            the CRL URI.
	 * @param issuerCertificate
	 *            the issuer certificate
	 * @param validationDate
	 *            the validation date.
	 * @return the X509 CRL, or <code>null</code> if not found.
	 */
	X509CRL findCrl(URI crlUri, X509Certificate issuerCertificate,
			Date validationDate);
}
