/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import be.fedict.trust.ServerNotAvailableException;
import be.fedict.trust.ServerType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;
import org.apache.http.util.EntityUtils;

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

	@Override
	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate, Date validationDate) throws ServerNotAvailableException {
		OCSPResp ocspResp = null;
		try {
			ocspResp = getOcspResponse(ocspUri, certificate, issuerCertificate);
		} catch (OperatorCreationException | CertificateEncodingException | OCSPException | IOException e) {
			throw new RuntimeException(e);
		}
		return ocspResp;
	}

	private OCSPResp getOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate) throws OperatorCreationException,
			CertificateEncodingException, OCSPException, IOException, ServerNotAvailableException {
		LOG.debug("OCSP URI: " + ocspUri);
		OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
		DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		CertificateID certId = new CertificateID(
				digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(issuerCertificate),
				certificate.getSerialNumber());
		ocspReqBuilder.addRequest(certId);

		OCSPReq ocspReq = ocspReqBuilder.build();
		byte[] ocspReqData = ocspReq.getEncoded();

		HttpPost httpPost = new HttpPost(ocspUri.toString());
		ContentType contentType = ContentType
				.create("application/ocsp-request");
		HttpEntity requestEntity = new ByteArrayEntity(ocspReqData, contentType);
		httpPost.addHeader("User-Agent", "jTrust OCSP Client");
		httpPost.setEntity(requestEntity);

		DefaultHttpClient httpClient = new DefaultHttpClient();
		if (null != this.networkConfig) {
			HttpHost proxy = new HttpHost(this.networkConfig.getProxyHost(),
					this.networkConfig.getProxyPort());
			httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY,
					proxy);
		}
		if (null != this.credentials) {
			this.credentials.init(httpClient.getCredentialsProvider());
		}

		HttpResponse httpResponse;
		int responseCode;
		try {
			httpResponse = httpClient.execute(httpPost);
			StatusLine statusLine = httpResponse.getStatusLine();
			responseCode = statusLine.getStatusCode();
		} catch (IOException e) {
			throw new ServerNotAvailableException("OCSP responder is down", ServerType.OCSP, e);
		}

		if (HttpURLConnection.HTTP_OK != responseCode) {
			throw new ServerNotAvailableException("OCSP server responded with status code " + responseCode, ServerType.OCSP);
		}

		Header responseContentTypeHeader = httpResponse
				.getFirstHeader("Content-Type");
		if (null == responseContentTypeHeader) {
			LOG.error("no Content-Type response header");
			return null;
		}
		String resultContentType = responseContentTypeHeader.getValue();
		if (!"application/ocsp-response".equals(resultContentType)) {
			LOG.error("result content type not application/ocsp-response");
                        LOG.error("actual content-type: " + resultContentType);
                        if ("text/html".equals(resultContentType)) {
                            LOG.error("content: " + EntityUtils.toString(httpResponse.getEntity()));
                        }
			return null;
		}

		Header responseContentLengthHeader = httpResponse
				.getFirstHeader("Content-Length");
		if (null != responseContentLengthHeader) {
			String resultContentLength = responseContentLengthHeader.getValue();
			if ("0".equals(resultContentLength)) {
				LOG.debug("no content returned");
				return null;
			}
		}

		HttpEntity httpEntity = httpResponse.getEntity();
		OCSPResp ocspResp = new OCSPResp(httpEntity.getContent());
		LOG.debug("OCSP response size: " + ocspResp.getEncoded().length
				+ " bytes");
		httpPost.releaseConnection();
		return ocspResp;
	}
}
