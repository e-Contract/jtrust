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

/**
 * Interface for trust linker components.
 * 
 * @author Frank Cornelis
 * 
 */
public interface TrustLinker {

	/**
	 * Verifies whether there is a trust link between the given certificates at
	 * the given validation date.
	 * 
	 * @param childCertificate
	 *            the X509 child certificate.
	 * @param certificate
	 *            the X509 parent certificate.
	 * @param validationDate
	 *            the validation date.
	 * @param revocationData
	 *            optional OCSP or CRL revocation data. Is <code>null</code> if
	 *            not specified.
	 * @return a {@link TrustLinkerResult} object containing the result and
	 *         optional reason if not valid. Returns <code>null</code> if the
	 *         trust is unknown.
	 */
	TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData);
}
