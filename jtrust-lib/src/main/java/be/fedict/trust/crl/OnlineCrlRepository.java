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

package be.fedict.trust.crl;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import be.fedict.trust.common.ServerNotAvailableException;
import be.fedict.trust.common.ServerType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.x509.NoSuchParserException;
import org.bouncycastle.x509.util.StreamParsingException;

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;

/**
 * Online CRL repository. This CRL repository implementation will download the
 * CRLs from the given CRL URIs.
 * 
 * @author Frank Cornelis
 */
public class OnlineCrlRepository implements CrlRepository {

	private static final Log LOG = LogFactory.getLog(OnlineCrlRepository.class);

	private final NetworkConfig networkConfig;

	private Credentials credentials;

	/**
	 * Main construtor.
	 * 
	 * @param networkConfig
	 *            the optional network configuration used for downloading CRLs.
	 */
	public OnlineCrlRepository(final NetworkConfig networkConfig) {
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
	public void setCredentials(final Credentials credentials) {
		this.credentials = credentials;
	}

	@Override
	public X509CRL findCrl(final URI crlUri, final X509Certificate issuerCertificate, final Date validationDate) throws ServerNotAvailableException {
		try {
			return getCrl(crlUri);
		} catch (final CRLException e) {
			LOG.debug("error parsing CRL: " + e.getMessage(), e);
			return null;
		} catch (final IOException | CertificateException | NoSuchProviderException | NoSuchParserException | StreamParsingException e) {
			LOG.error("find CRL error: " + e.getMessage(), e);
			return null;
		}
	}

	private X509CRL getCrl(final URI crlUri) throws IOException,
			CertificateException, CRLException, NoSuchProviderException,
			NoSuchParserException, StreamParsingException, ServerNotAvailableException {
		final DefaultHttpClient httpClient = new DefaultHttpClient();

		if (null != this.networkConfig) {
			final HttpHost proxy = new HttpHost(this.networkConfig.getProxyHost(), this.networkConfig.getProxyPort());
			httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
		}

		if (null != this.credentials) {
			this.credentials.init(httpClient.getCredentialsProvider());
		}

		final String downloadUrl = crlUri.toURL().toString();
		LOG.debug("downloading CRL from: " + downloadUrl);
		final HttpGet httpGet = new HttpGet(downloadUrl);
		httpGet.addHeader("User-Agent", "jTrust CRL Client");

		final HttpResponse httpResponse = httpClient.execute(httpGet);
		final StatusLine statusLine = httpResponse.getStatusLine();
		final int statusCode = statusLine.getStatusCode();

		if (statusCode >= HttpURLConnection.HTTP_INTERNAL_ERROR) {
			LOG.error("CRL server responded with status code: " + statusCode );
			throw new ServerNotAvailableException("CRL server responded with status code " + statusCode, ServerType.CRL);
		}

		if (HttpURLConnection.HTTP_OK != statusCode) {
			LOG.debug("HTTP status code: " + statusCode);
			return null;
		}

		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		LOG.debug("certificate factory provider: " + certificateFactory.getProvider().getName());
		LOG.debug("certificate factory class: " + certificateFactory.getClass().getName());

		final HttpEntity httpEntity = httpResponse.getEntity();
		try (final InputStream content = httpEntity.getContent()) {
			final X509CRL crl = (X509CRL) certificateFactory.generateCRL(content);
			if (crl != null) {
				LOG.debug("X509CRL class: " + crl.getClass().getName());
				LOG.debug("CRL size: " + crl.getEncoded().length + " bytes");
			} else {
				LOG.debug("X509CRL is null");
			}
			return crl;
		} finally {
			httpGet.releaseConnection();
		}
	}
}
