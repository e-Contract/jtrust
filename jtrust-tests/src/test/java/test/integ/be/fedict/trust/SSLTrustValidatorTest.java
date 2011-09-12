/*
 * Java Trust Project.
 * Copyright (C) 2011 Frank Cornelis.
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

package test.integ.be.fedict.trust;

import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.trust.MemoryCertificateRepository;
import be.fedict.trust.TrustValidator;

public class SSLTrustValidatorTest {

	private static final Log LOG = LogFactory
			.getLog(SSLTrustValidatorTest.class);

	@Test
	public void test() throws Exception {
		// URL url = new URL("https://www.fortisbanking.be");
		//URL url = new URL("https://www.facebook.com");
		//URL url = new URL("https://www.twitter.com");
		URL url = new URL("https://www.mozilla.org");
		HttpsURLConnection connection = (HttpsURLConnection) url
				.openConnection();
		connection.connect();
		Certificate[] serverCertificates = connection.getServerCertificates();
		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		for (Certificate certificate : serverCertificates) {
			X509Certificate x509Cert = (X509Certificate) certificate;
			certificateChain.add(x509Cert);
			LOG.debug("subject: " + x509Cert.getSubjectX500Principal());
			LOG.debug("issuer: " + x509Cert.getIssuerX500Principal());
		}

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository
				.addTrustPoint((X509Certificate) serverCertificates[serverCertificates.length - 1]);
		TrustValidator trustValidator = new TrustValidator(
				certificateRepository);

		trustValidator.isTrusted(certificateChain);
	}
}
