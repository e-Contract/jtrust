/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
 * Copyright (C) 2014-2019 e-Contract.be BVBA.
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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.NetworkConfig;

/**
 * An implementation on an online OCSP repository where you can override the
 * OCSP URI's. Can be used to test backup OCSP solutions.
 * 
 * @author Frank Cornelis
 * 
 */
public class OverrideOnlineOcspRepository extends OnlineOcspRepository {

	private static final Logger LOGGER = LoggerFactory.getLogger(OverrideOnlineOcspRepository.class);

	private final Map<URI, URI> overrideURIs;

	public OverrideOnlineOcspRepository() {
		super();
		this.overrideURIs = new HashMap<>();
	}

	public OverrideOnlineOcspRepository(NetworkConfig networkConfig) {
		super(networkConfig);
		this.overrideURIs = new HashMap<>();
	}

	public void overrideOCSP(URI originalOcspUri, URI newOcspUri) {
		this.overrideURIs.put(originalOcspUri, newOcspUri);
	}

	@Override
	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate, X509Certificate issuerCertificate,
			Date validationDate) {
		URI overrideOcspUri = this.overrideURIs.get(ocspUri);
		if (null != overrideOcspUri) {
			LOGGER.debug("Overriding OCSP URI: {} with {}", ocspUri, overrideOcspUri);
			ocspUri = overrideOcspUri;
		} else {
			LOGGER.debug("not overriding OCSP URI: {}", ocspUri);
		}
		return super.findOcspResponse(ocspUri, certificate, issuerCertificate, validationDate);
	}
}
