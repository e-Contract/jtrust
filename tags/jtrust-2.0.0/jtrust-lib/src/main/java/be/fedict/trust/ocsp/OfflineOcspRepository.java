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

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Off line OCSP repository. This implementation receives a list of
 * {@link OCSPResp} objects.
 * <p/>
 * TODO: when multiple OCSPs match, we should return the one closest to the
 * validation date.
 * 
 * @author Frank Cornelis
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

	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate, Date validationDate) {

		LOG.debug("find OCSP response");

		DigestCalculatorProvider digCalcProv;
		try {
			digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(
					BouncyCastleProvider.PROVIDER_NAME).build();
		} catch (OperatorCreationException e) {
			throw new RuntimeException(e);
		}

		CertificateID certId;
		try {
			certId = new CertificateID(
					digCalcProv.get(CertificateID.HASH_SHA1),
					new JcaX509CertificateHolder(issuerCertificate),
					certificate.getSerialNumber());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		try {
			for (OCSPResp ocspResp : this.ocspResponses) {
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