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

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

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
            OCSPResp ocspResp = null;
            try {
                ocspResp = getOcspResponse(ocspUri, certificate,
                        issuerCertificate);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return ocspResp;
	}

	private OCSPResp getOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate) throws Exception {
		LOG.debug("OCSP URI: " + ocspUri);
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        DigestCalculatorProvider
            digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCertificate), certificate.getSerialNumber());
        ocspReqBuilder.addRequest(certId);

        OCSPReq ocspReq = ocspReqBuilder.build();
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

		OCSPResp ocspResp = new OCSPResp(postMethod.getResponseBody());
		LOG.debug("OCSP response size: " + ocspResp.getEncoded().length
				+ " bytes");
		return ocspResp;
	}
}
