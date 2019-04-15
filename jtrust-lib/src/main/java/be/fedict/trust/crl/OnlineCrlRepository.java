/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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

package be.fedict.trust.crl;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.x509.NoSuchParserException;
import org.bouncycastle.x509.util.StreamParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;

/**
 * Online CRL repository. This CRL repository implementation will download the
 * CRLs from the given CRL URIs.
 * 
 * @author Frank Cornelis
 */
public class OnlineCrlRepository implements CrlRepository {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnlineCrlRepository.class);

	private final NetworkConfig networkConfig;

	private Credentials credentials;

	/**
	 * Main construtor.
	 * 
	 * @param networkConfig
	 *            the optional network configuration used for downloading CRLs.
	 */
	public OnlineCrlRepository(NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	/**
	 * Default constructor.
	 */
	public OnlineCrlRepository() {
		this(null);
	}

	/**
	 * Sets the credentials to use to access protected CRL services.
	 * 
	 * @param credentials
	 */
	public void setCredentials(Credentials credentials) {
		this.credentials = credentials;
	}

	@Override
	public X509CRL findCrl(URI crlUri, X509Certificate issuerCertificate, Date validationDate) {
		try {
			return getCrl(crlUri);
		} catch (CRLException e) {
			LOGGER.debug("error parsing CRL: {}", e.getMessage(), e);
			return null;
		} catch (Exception e) {
			LOGGER.error("find CRL error: {}", e.getMessage(), e);
			return null;
		}
	}

	private X509CRL getCrl(URI crlUri) throws IOException, CertificateException, CRLException, NoSuchProviderException,
			NoSuchParserException, StreamParsingException {
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

		String downloadUrl = crlUri.toURL().toString();
		LOGGER.debug("downloading CRL from: {}", downloadUrl);
		HttpGet httpGet = new HttpGet(downloadUrl);
		httpGet.addHeader("User-Agent", "jTrust CRL Client");
		HttpResponse httpResponse = httpClient.execute(httpGet);
		StatusLine statusLine = httpResponse.getStatusLine();
		int statusCode = statusLine.getStatusCode();
		if (HttpURLConnection.HTTP_OK != statusCode) {
			LOGGER.debug("HTTP status code: {}", statusCode);
			return null;
		}

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		LOGGER.debug("certificate factory provider: {}", certificateFactory.getProvider().getName());
		LOGGER.debug("certificate factory class: {}", certificateFactory.getClass().getName());
		HttpEntity httpEntity = httpResponse.getEntity();
		X509CRL crl = (X509CRL) certificateFactory.generateCRL(httpEntity.getContent());
		httpGet.releaseConnection();
		if (null == crl) {
			LOGGER.error("null CRL");
			return null;
		}
		LOGGER.debug("X509CRL class: {}", crl.getClass().getName());
		LOGGER.debug("CRL size: {} bytes", crl.getEncoded().length);
		return crl;
	}
}
