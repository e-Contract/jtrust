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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.ocsp.*;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

/**
 * Off line OCSP repository. This implementation receives a list of
 * {@link OCSPResp} objects.
 * 
 * @author wvdhaute
 */
public class OfflineOcspRepository implements OcspRepository {

	private static final Log LOG = LogFactory
			.getLog(OfflineOcspRepository.class);

	private final List<OCSPResp> ocspResponses;

	/**
	 * Main constructor
	 * 
	 * @param encodedOcspResponses
	 *            the list of encoded OCSP responses that can be queried.
	 * @throws IOException
	 */
	public OfflineOcspRepository(List<byte[]> encodedOcspResponses)
			throws IOException {

		this.ocspResponses = new LinkedList<OCSPResp>();
		for (byte[] encodedOcspResponse : encodedOcspResponses) {
			OCSPResp ocspResponse = new OCSPResp(encodedOcspResponse);
			ocspResponses.add(ocspResponse);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate) {

		LOG.debug("find OCSP response");

		try {
			for (OCSPResp ocspResp : this.ocspResponses) {

				CertificateID certId = new CertificateID(
						CertificateID.HASH_SHA1, issuerCertificate,
						certificate.getSerialNumber());
				BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp
						.getResponseObject();
				for (SingleResp singleResp : basicOCSPResp.getResponses()) {
					if (singleResp.getCertID().equals(certId)) {
						LOG.debug("OCSP response found");
						return ocspResp;
					}
				}
			}
		} catch (OCSPException e) {
			LOG.error("OCSPException: " + e.getMessage(), e);
			return null;
		}

		LOG.debug("OCSP response not found");
		return null;
	}

}
