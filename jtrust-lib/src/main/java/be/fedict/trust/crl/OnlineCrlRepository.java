/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014-2023 e-Contract.be BV.
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
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
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
	 * @param networkConfig the optional network configuration used for downloading
	 *                      CRLs.
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
		HttpClientContext httpClientContext = HttpClientContext.create();
		if (null != this.credentials) {
			this.credentials.init(httpClientContext);
		}
		RequestConfig.Builder requestConfigBuilder = RequestConfig.custom().setConnectionRequestTimeout(timeout,
				TimeUnit.SECONDS);
		RequestConfig requestConfig = requestConfigBuilder.build();
		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		httpClientBuilder.setDefaultRequestConfig(requestConfig);
		if (null != this.networkConfig) {
			HttpHost proxy = new HttpHost(this.networkConfig.getProxyHost(), this.networkConfig.getProxyPort());
			httpClientBuilder.setProxy(proxy);
		}
		BasicHttpClientConnectionManager basicHttpClientConnectionManager = new BasicHttpClientConnectionManager();
		ConnectionConfig connectionConfig = ConnectionConfig.custom().setConnectTimeout(timeout, TimeUnit.SECONDS)
				.setSocketTimeout(timeout, TimeUnit.SECONDS).build();
		basicHttpClientConnectionManager.setConnectionConfig(connectionConfig);
		httpClientBuilder.setConnectionManager(basicHttpClientConnectionManager);
		try (CloseableHttpClient httpClient = httpClientBuilder.build()) {
			String downloadUrl = crlUri.toURL().toString();
			LOGGER.debug("downloading CRL from: {}", downloadUrl);
			HttpGet httpGet = new HttpGet(downloadUrl);
			httpGet.addHeader("User-Agent", "jTrust CRL Client");
			HttpClientResponseHandler<X509CRL> responseHandler = (ClassicHttpResponse httpResponse) -> {
				int statusCode = httpResponse.getCode();
				if (HttpURLConnection.HTTP_OK != statusCode) {
					LOGGER.error("HTTP status code: {}", statusCode);
					return null;
				}

				// not guaranteed to be thread-safe
				CertificateFactory certificateFactory;
				try {
					certificateFactory = CertificateFactory.getInstance("X.509", "BC");
				} catch (CertificateException | NoSuchProviderException ex) {
					LOGGER.error("error: " + ex.getMessage(), ex);
					return null;
				}
				HttpEntity httpEntity = httpResponse.getEntity();
				X509CRL crl;
				try {
					crl = (X509CRL) certificateFactory.generateCRL(httpEntity.getContent());
				} catch (CRLException ex) {
					LOGGER.error("error: " + ex.getMessage(), ex);
					return null;
				}
				if (null == crl) {
					LOGGER.error("null CRL");
					return null;
				}
				try {
					LOGGER.debug("CRL size: {} bytes", crl.getEncoded().length);
				} catch (CRLException ex) {
					LOGGER.error("error: " + ex.getMessage(), ex);
					return null;
				}
				return crl;
			};
			X509CRL crl = httpClient.execute(httpGet, httpClientContext, responseHandler);
			return crl;
		}
	}
}
