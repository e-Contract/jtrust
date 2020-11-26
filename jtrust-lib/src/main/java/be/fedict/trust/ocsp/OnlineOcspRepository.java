/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014-2020 e-Contract.be BV.
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

import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private static final Logger LOGGER = LoggerFactory.getLogger(OnlineOcspRepository.class);

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
	public OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate, X509Certificate issuerCertificate,
			Date validationDate) {
		if (null == ocspUri) {
			return null;
		}
		OCSPResp ocspResp = null;
		try {
			ocspResp = getOcspResponse(ocspUri, certificate, issuerCertificate);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return ocspResp;
	}

	private OCSPResp getOcspResponse(URI ocspUri, X509Certificate certificate, X509Certificate issuerCertificate)
			throws Exception {
		LOGGER.debug("OCSP URI: {}", ocspUri);
		OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
		DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(issuerCertificate), certificate.getSerialNumber());
		ocspReqBuilder.addRequest(certId);

		byte[] nonce = new byte[20];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(nonce);
		DEROctetString encodedNonceValue = new DEROctetString(new DEROctetString(nonce).getEncoded());
		Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, encodedNonceValue);
		Extensions extensions = new Extensions(extension);
		ocspReqBuilder.setRequestExtensions(extensions);

		OCSPReq ocspReq = ocspReqBuilder.build();
		byte[] ocspReqData = ocspReq.getEncoded();

		HttpPost httpPost = new HttpPost(ocspUri.toString());
		ContentType contentType = ContentType.create("application/ocsp-request");
		HttpEntity requestEntity = new ByteArrayEntity(ocspReqData, contentType);
		httpPost.addHeader("User-Agent", "jTrust OCSP Client");
		httpPost.setEntity(requestEntity);

		int timeout = 10;
		RequestConfig.Builder requestConfigBuilder = RequestConfig.custom().setConnectTimeout(timeout * 1000)
				.setConnectionRequestTimeout(timeout * 1000).setSocketTimeout(timeout * 1000);

		if (null != this.networkConfig) {
			HttpHost proxy = new HttpHost(this.networkConfig.getProxyHost(), this.networkConfig.getProxyPort());
			requestConfigBuilder.setProxy(proxy);
		}
		HttpClientContext httpClientContext = HttpClientContext.create();
		if (null != this.credentials) {
			this.credentials.init(httpClientContext);
		}
		RequestConfig requestConfig = requestConfigBuilder.build();
		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		httpClientBuilder.setDefaultRequestConfig(requestConfig);
		HttpClient httpClient = httpClientBuilder.build();

		HttpResponse httpResponse;
		int responseCode;
		try {
			httpResponse = httpClient.execute(httpPost, httpClientContext);
			StatusLine statusLine = httpResponse.getStatusLine();
			responseCode = statusLine.getStatusCode();
		} catch (ConnectException e) {
			LOGGER.error("OCSP responder is down");
			return null;
		}

		if (HttpURLConnection.HTTP_OK != responseCode) {
			LOGGER.error("HTTP response code: {}", responseCode);
			return null;
		}

		Header responseContentTypeHeader = httpResponse.getFirstHeader("Content-Type");
		if (null == responseContentTypeHeader) {
			LOGGER.error("no Content-Type response header");
			return null;
		}
		String resultContentType = responseContentTypeHeader.getValue();
		if (!"application/ocsp-response".equals(resultContentType)) {
			LOGGER.error("result content type not application/ocsp-response");
			LOGGER.error("actual content-type: {}", resultContentType);
			if ("text/html".equals(resultContentType)) {
				LOGGER.error("content: {}", EntityUtils.toString(httpResponse.getEntity()));
			}
			return null;
		}

		Header responseContentLengthHeader = httpResponse.getFirstHeader("Content-Length");
		if (null != responseContentLengthHeader) {
			String resultContentLength = responseContentLengthHeader.getValue();
			if ("0".equals(resultContentLength)) {
				LOGGER.debug("no content returned");
				return null;
			}
		}

		HttpEntity httpEntity = httpResponse.getEntity();
		OCSPResp ocspResp = new OCSPResp(httpEntity.getContent());
		LOGGER.debug("OCSP response size: {} bytes", ocspResp.getEncoded().length);
		httpPost.releaseConnection();

		int ocspRespStatus = ocspResp.getStatus();
		if (OCSPResponseStatus.SUCCESSFUL != ocspRespStatus) {
			LOGGER.debug("OCSP response status: {}", ocspRespStatus);
			return ocspResp;
		}

		Object responseObject = ocspResp.getResponseObject();
		BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;
		Extension nonceExtension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		if (null == nonceExtension) {
			LOGGER.debug("no nonce extension in response");
			return ocspResp;
		}

		ASN1OctetString nonceExtensionValue = extension.getExtnValue();
		ASN1Primitive nonceValue = ASN1Primitive.fromByteArray(nonceExtensionValue.getOctets());
		byte[] responseNonce = ((DEROctetString) nonceValue).getOctets();
		if (!Arrays.areEqual(nonce, responseNonce)) {
			LOGGER.error("nonce mismatch");
			return null;
		}
		LOGGER.debug("nonce match");

		return ocspResp;
	}
}
