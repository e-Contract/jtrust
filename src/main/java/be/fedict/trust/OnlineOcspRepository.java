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

import java.io.IOException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.X509Certificate;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;

public class OnlineOcspRepository implements OcspRepository {

	private static final Log LOG = LogFactory
			.getLog(OnlineOcspRepository.class);

	private final NetworkConfig networkConfig;

	public OnlineOcspRepository(NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	public OnlineOcspRepository() {
		this(null);
	}

	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate) {
		LOG.debug("OCSP URI: " + ocspUri);
		byte[] ocspReqData;
		try {
			OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
			CertificateID certId = new CertificateID(CertificateID.HASH_SHA1,
					issuerCertificate, certificate.getSerialNumber());
			ocspReqGenerator.addRequest(certId);
			OCSPReq ocspReq = ocspReqGenerator.generate();
			ocspReqData = ocspReq.getEncoded();
		} catch (OCSPException e) {
			throw new RuntimeException("OCSP error: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new RuntimeException("I/O error: " + e.getMessage(), e);
		}

		PostMethod postMethod = new PostMethod(ocspUri.toString());
		RequestEntity requestEntity = new ByteArrayRequestEntity(ocspReqData,
				"application/ocsp-request");
		postMethod.addRequestHeader("User-Agent", "jTrust OCSP Client");
		postMethod.setRequestEntity(requestEntity);

		HttpClient httpClient = new HttpClient();
		if (null != this.networkConfig) {
			httpClient.getHostConfiguration().setProxy(
					this.networkConfig.getProxyHost(),
					this.networkConfig.getProxyPort());
		}

		int responseCode;
		try {
			httpClient.executeMethod(postMethod);
			responseCode = postMethod.getStatusCode();
		} catch (ConnectException e) {
			LOG.debug("OCSP responder is down");
			return null;
		} catch (IOException e) {
			throw new RuntimeException("I/O error: " + e.getMessage(), e);
		}

		if (HttpURLConnection.HTTP_OK != responseCode) {
			LOG.error("HTTP response code: " + responseCode);
			return null;
		}
		Header responseContentTypeHeader = postMethod
				.getResponseHeader("Content-Type");
		if (null == responseContentTypeHeader) {
			return null;
		}
		String resultContentType = responseContentTypeHeader.getValue();
		if (!"application/ocsp-response".equals(resultContentType)) {
			LOG.warn("result content type not application/ocsp-response");
		}
		OCSPResp ocspResp;
		try {
			ocspResp = new OCSPResp(postMethod.getResponseBodyAsStream());
		} catch (IOException e) {
			throw new RuntimeException("OCSP response decoding error: "
					+ e.getMessage(), e);
		}
		return ocspResp;
	}
}
