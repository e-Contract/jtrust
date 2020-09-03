/*
 * Java Trust Project.
 * Copyright (C) 2011 Frank Cornelis.
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

package test.integ.be.fedict.trust;

import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.commons.eid.jca.BeIDProvider;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.repository.MemoryCertificateRepository;

public class SSLTrustValidatorTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(SSLTrustValidatorTest.class);

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testTestEIDBelgiumBe() throws Exception {
		Security.addProvider(new BeIDProvider());

		SSLContext sslContext = SSLContext.getInstance("TLS");
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("BeID");

		keyManagerFactory.init(null);
		SecureRandom secureRandom = new SecureRandom();
		sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[] { new ClientTestX509TrustManager() },
				secureRandom);
		SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("test.eid.belgium.be", 443);
		LOGGER.debug("socket created");
		SSLSession sslSession = sslSocket.getSession();
		Certificate[] peerCertificates = sslSession.getPeerCertificates();
		for (Certificate peerCertificate : peerCertificates) {
			LOGGER.debug("peer certificate: {}", ((X509Certificate) peerCertificate).getSubjectX500Principal());
		}

		MemoryCertificateRepository repository = new MemoryCertificateRepository();
		repository.addTrustPoint((X509Certificate) peerCertificates[peerCertificates.length - 1]);

		TrustValidator trustValidator = new TrustValidator(repository);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);
		trustValidator.isTrusted(peerCertificates);
	}

	private static final class ClientTestX509TrustManager implements X509TrustManager {

		private static final Log LOG = LogFactory.getLog(ClientTestX509TrustManager.class);

		@Override
		public void checkClientTrusted(final X509Certificate[] chain, final String authType)
				throws CertificateException {
			LOG.debug("checkClientTrusted");
		}

		@Override
		public void checkServerTrusted(final X509Certificate[] chain, final String authType)
				throws CertificateException {
			LOG.debug("checkServerTrusted: " + authType);
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			LOG.debug("getAcceptedIssuers");
			return null;
		}

	}

	@Test
	public void testValidation() throws Exception {
		validate("https://www.e-contract.be/");
		validate("https://eid.belgium.be/");
		validate("https://www.cloudflare.com/");
		validate("https://www.facebook.com");
		validate("https://www.twitter.com");
		validate("https://www.mozilla.org");
		validate("https://www.verisign.com/");
		validate("https://slashdot.org");
		validate("https://google.com");
		validate("https://linkedin.com");
	}

	private void validate(String domain) throws Exception {
		URL url = new URL(domain);
		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		connection.connect();
		Certificate[] serverCertificates = connection.getServerCertificates();
		List<X509Certificate> certificateChain = new LinkedList<>();
		for (Certificate certificate : serverCertificates) {
			X509Certificate x509Cert = (X509Certificate) certificate;
			certificateChain.add(x509Cert);
			LOGGER.debug("certificate subject: {}", x509Cert.getSubjectX500Principal());
			LOGGER.debug("certificate issuer: {}", x509Cert.getIssuerX500Principal());
		}

		X509Certificate rootCertificate = certificateChain.get(certificateChain.size() - 1);
		if (!rootCertificate.getSubjectX500Principal().equals(rootCertificate.getIssuerX500Principal())) {
			LOGGER.error("no a self-signed root in chain");
			rootCertificate = getTrustAnchor(rootCertificate);
			certificateChain.add(rootCertificate);
		}

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository.addTrustPoint(rootCertificate);

		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		// next is kind of a default trust linked pattern.
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		// operate
		trustValidator.isTrusted(certificateChain);
	}

	private X509Certificate getTrustAnchor(X509Certificate certificate) throws Exception {
		String caCertsFile = System.getProperty("java.home") + "/lib/security/cacerts";
		FileInputStream is = new FileInputStream(caCertsFile);
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		String password = "changeit";
		keystore.load(is, password.toCharArray());

		PKIXParameters params = new PKIXParameters(keystore);

		Iterator it = params.getTrustAnchors().iterator();
		while (it.hasNext()) {
			TrustAnchor ta = (TrustAnchor) it.next();
			X509Certificate rootCertificate = ta.getTrustedCert();
			if (certificate.getIssuerX500Principal().equals(rootCertificate.getSubjectX500Principal())) {
				return rootCertificate;
			}
		}
		throw new IllegalArgumentException();
	}
}
