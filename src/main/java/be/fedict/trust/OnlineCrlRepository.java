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
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class OnlineCrlRepository implements CrlRepository {

	private static final Log LOG = LogFactory.getLog(OnlineCrlRepository.class);

	private final NetworkConfig networkConfig;

	public OnlineCrlRepository(NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	public OnlineCrlRepository() {
		this(null);
	}

	public X509CRL findCrl(URI crlUri, Date validationDate) {
		try {
			X509CRL crl = getCrl(crlUri);
			return crl;
		} catch (Exception e) {
			LOG.error("getCRL: " + e.getMessage(), e);
			return null;
		}
	}

	private X509CRL getCrl(URI crlUri) throws HttpException, IOException,
			CertificateException, CRLException {
		HttpClient httpClient = new HttpClient();
		if (null != this.networkConfig) {
			httpClient.getHostConfiguration().setProxy(
					this.networkConfig.getProxyHost(),
					this.networkConfig.getProxyPort());
		}
		String downloadUrl = crlUri.toURL().toString();
		LOG.debug("downloading CRL from: " + downloadUrl);
		GetMethod getMethod = new GetMethod(downloadUrl);
		int statusCode = httpClient.executeMethod(getMethod);
		if (HttpURLConnection.HTTP_OK != statusCode) {
			return null;
		}
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509CRL crl = (X509CRL) certificateFactory.generateCRL(getMethod
				.getResponseBodyAsStream());
		LOG.debug("CRL size: " + crl.getEncoded().length + " bytes");
		return crl;
	}
}
