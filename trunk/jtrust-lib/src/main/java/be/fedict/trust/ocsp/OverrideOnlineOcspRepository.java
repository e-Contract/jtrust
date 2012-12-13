/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
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
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.trust.NetworkConfig;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * An implementation on an online OCSP repository where you can override the
 * OCSP URI's. Can be used to test backup OCSP solutions.
 * 
 * @author Frank Cornelis
 * 
 */
public class OverrideOnlineOcspRepository extends OnlineOcspRepository {

	private static final Log LOG = LogFactory
			.getLog(OverrideOnlineOcspRepository.class);

	private final Map<URI, URI> overrideURIs;

	public OverrideOnlineOcspRepository() {
		super();
		this.overrideURIs = new HashMap<URI, URI>();
	}

	public OverrideOnlineOcspRepository(NetworkConfig networkConfig) {
		super(networkConfig);
		this.overrideURIs = new HashMap<URI, URI>();
	}

	public void overrideOCSP(URI originalOcspUri, URI newOcspUri) {
		this.overrideURIs.put(originalOcspUri, newOcspUri);
	}

	@Override
	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
                                                                X509Certificate issuerCertificate) {
		URI overrideOcspUri = this.overrideURIs.get(ocspUri);
		if (null != overrideOcspUri) {
			LOG.debug("Overriding OCSP URI: " + ocspUri + " with "
					+ overrideOcspUri);
			ocspUri = overrideOcspUri;
		} else {
			LOG.debug("not overriding OCSP URI: " + ocspUri);
		}
		return super.findOcspResponse(ocspUri, certificate, issuerCertificate);
	}
}
