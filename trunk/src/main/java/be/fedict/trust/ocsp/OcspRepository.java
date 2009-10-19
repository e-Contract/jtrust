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

package be.fedict.trust.ocsp;

import java.net.URI;
import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.OCSPResp;

/**
 * Interface for OCSP repository components.
 * 
 * @author Frank Cornelis
 * 
 */
public interface OcspRepository {

	/**
	 * Finds the requested OCSP response in this OCSP repository.
	 * 
	 * @param ocspUri
	 *            the OCSP responder URI.
	 * @param certificate
	 *            the X509 certificate.
	 * @param issuerCertificate
	 *            the X509 issuer certificate.
	 * @return the OCSP response, or <code>null</code> if not found.
	 */
	OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate);
}
