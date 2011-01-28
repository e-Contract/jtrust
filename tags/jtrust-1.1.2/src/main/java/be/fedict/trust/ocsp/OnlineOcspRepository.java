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
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.X509Certificate;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpState;
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

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder
 * to retrieve the OCSP response.
 * 
 * @author Frank Cornelis
 * 
 */
public class OnlineOcspRepository implements OcspRepository {

	private static final Log LOG = LogFactory
			.getLog(OnlineOcspRepository.class);

	private final NetworkConfig networkConfig;

	private Credentials credentials;

	/**
	 * Main construtor.
	 * 
	 * @param networkConfig
	 *            the optional network configuration used during OCSP Responder
	 *            communication.
	 */
	public OnlineOcspRepository(NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	/**
	 * Default constructor.
	 */
	public OnlineOcspRepository() {
		this(null);
	}

	/**
	 * Sets the credentials to use to access protected OCSP services.
	 * 
	 * @param credentials
	 */
	public void setCredentials(Credentials credentials) {
		this.credentials = credentials;
	}

	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate) {
		try {
			OCSPResp ocspResp = getOcspResponse(ocspUri, certificate,
					issuerCertificate);
			return ocspResp;
		} catch (OCSPException e) {
			LOG.debug("OCSP error: " + e.getMessage(), e);
			return null;
		} catch (IOException e) {
			LOG.debug("I/O error: " + e.getMessage(), e);
			return null;
		}
	}

	private OCSPResp getOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate) throws OCSPException,
			IOException {
		LOG.debug("OCSP URI: " + ocspUri);
		OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
		CertificateID certId = new CertificateID(CertificateID.HASH_SHA1,
				issuerCertificate, certificate.getSerialNumber());
		ocspReqGenerator.addRequest(certId);
		OCSPReq ocspReq = ocspReqGenerator.generate();
		byte[] ocspReqData = ocspReq.getEncoded();

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
		if (null != this.credentials) {
			HttpState httpState = httpClient.getState();
			this.credentials.init(httpState);
		}

		int responseCode;
		try {
			httpClient.executeMethod(postMethod);
			responseCode = postMethod.getStatusCode();
		} catch (ConnectException e) {
			LOG.debug("OCSP responder is down");
			return null;
		}

		if (HttpURLConnection.HTTP_OK != responseCode) {
			LOG.error("HTTP response code: " + responseCode);
			return null;
		}

		Header responseContentTypeHeader = postMethod
				.getResponseHeader("Content-Type");
		if (null == responseContentTypeHeader) {
			LOG.debug("no Content-Type response header");
			return null;
		}
		String resultContentType = responseContentTypeHeader.getValue();
		if (!"application/ocsp-response".equals(resultContentType)) {
			LOG.debug("result content type not application/ocsp-response");
			return null;
		}

		Header responseContentLengthHeader = postMethod
				.getResponseHeader("Content-Length");
		if (null != responseContentLengthHeader) {
			String resultContentLength = responseContentLengthHeader.getValue();
			if ("0".equals(resultContentLength)) {
				LOG.debug("no content returned");
				return null;
			}
		}

		OCSPResp ocspResp = new OCSPResp(postMethod.getResponseBodyAsStream());
		LOG.debug("OCSP response size: " + ocspResp.getEncoded().length
				+ " bytes");
		return ocspResp;
	}
}
