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

package be.fedict.trust.crl;

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.x509.NoSuchParserException;
import org.bouncycastle.x509.util.StreamParsingException;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.Date;

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

	public X509CRL findCrl(URI crlUri, X509Certificate issuerCertificate,
			Date validationDate) {
		try {
			return getCrl(crlUri);
		} catch (CRLException e) {
			LOG.debug("error parsing CRL: " + e.getMessage(), e);
			return null;
		} catch (Exception e) {
			LOG.error("find CRL error: " + e.getMessage(), e);
			return null;
		}
	}

	private X509CRL getCrl(URI crlUri) throws IOException,
			CertificateException, CRLException, NoSuchProviderException,
			NoSuchParserException, StreamParsingException {
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
		String downloadUrl = crlUri.toURL().toString();
		LOG.debug("downloading CRL from: " + downloadUrl);
		GetMethod getMethod = new GetMethod(downloadUrl);
		getMethod.addRequestHeader("User-Agent", "jTrust CRL Client");
		int statusCode = httpClient.executeMethod(getMethod);
		if (HttpURLConnection.HTTP_OK != statusCode) {
			LOG.debug("HTTP status code: " + statusCode);
			return null;
		}

		CertificateFactory certificateFactory = CertificateFactory.getInstance(
				"X.509", "BC");
		X509CRL crl = (X509CRL) certificateFactory.generateCRL(getMethod
				.getResponseBodyAsStream());
		LOG.debug("CRL size: " + crl.getEncoded().length + " bytes");
		return crl;
	}
}
