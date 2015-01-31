/*
 * Java Trust Project.
 * Copyright (C) 2011 Frank Cornelis.
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

package test.integ.be.fedict.trust;

import java.net.Proxy;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
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
import org.junit.Before;
import org.junit.Test;

import be.fedict.commons.eid.jca.BeIDProvider;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.repository.MemoryCertificateRepository;

public class SSLTrustValidatorTest {

	private static final Log LOG = LogFactory
			.getLog(SSLTrustValidatorTest.class);

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testTestEIDBelgiumBe() throws Exception {
		Security.addProvider(new BeIDProvider());

		SSLContext sslContext = SSLContext.getInstance("TLS");
		KeyManagerFactory keyManagerFactory = KeyManagerFactory
				.getInstance("BeID");

		keyManagerFactory.init(null);
		SecureRandom secureRandom = new SecureRandom();
		sslContext.init(keyManagerFactory.getKeyManagers(),
				new TrustManager[] { new ClientTestX509TrustManager() },
				secureRandom);
		SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(
				"test.eid.belgium.be", 443);
		LOG.debug("socket created");
		SSLSession sslSession = sslSocket.getSession();
		Certificate[] peerCertificates = sslSession.getPeerCertificates();
		for (Certificate peerCertificate : peerCertificates) {
			LOG.debug("peer certificate: "
					+ ((X509Certificate) peerCertificate)
							.getSubjectX500Principal());
		}

		MemoryCertificateRepository repository = new MemoryCertificateRepository();
		repository
				.addTrustPoint((X509Certificate) peerCertificates[peerCertificates.length - 1]);

		TrustValidator trustValidator = new TrustValidator(repository);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);
		trustValidator.isTrusted(peerCertificates);
	}

	private static final class ClientTestX509TrustManager implements
			X509TrustManager {

		private static final Log LOG = LogFactory
				.getLog(ClientTestX509TrustManager.class);

		@Override
		public void checkClientTrusted(final X509Certificate[] chain,
				final String authType) throws CertificateException {
			LOG.debug("checkClientTrusted");
		}

		@Override
		public void checkServerTrusted(final X509Certificate[] chain,
				final String authType) throws CertificateException {
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
		Proxy proxy = Proxy.NO_PROXY;
		// Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(
		// "proxy.yourict.net", 8080));
		NetworkConfig networkConfig = null; // new
											// NetworkConfig("proxy.yourict.net",
											// 8080);
		// URL url = new URL("https://eid.belgium.be/"); // OK
		// URL url = new URL("https://www.fortisbanking.be"); // OK
		// URL url = new URL("https://www.e-contract.be/"); // OK
		// URL url = new URL("https://idp.services.belgium.be"); // OK
		// URL url = new URL("https://idp.int.belgium.be"); // OK
		URL url = new URL("https://test.eid.belgium.be/");

		// URL url = new URL("https://www.facebook.com");
		// URL url = new URL("https://www.twitter.com");
		// URL url = new URL("https://www.mozilla.org");
		// URL url = new URL("https://www.verisign.com/");
		HttpsURLConnection connection = (HttpsURLConnection) url
				.openConnection(proxy);
		connection.connect();
		Certificate[] serverCertificates = connection.getServerCertificates();
		List<X509Certificate> certificateChain = new LinkedList<>();
		for (Certificate certificate : serverCertificates) {
			X509Certificate x509Cert = (X509Certificate) certificate;
			certificateChain.add(x509Cert);
			LOG.debug("certificate subject: "
					+ x509Cert.getSubjectX500Principal());
			LOG.debug("certificate issuer: "
					+ x509Cert.getIssuerX500Principal());
		}

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository.addTrustPoint(certificateChain
				.get(certificateChain.size() - 1));
		TrustValidator trustValidator = new TrustValidator(
				certificateRepository);
		trustValidator.setAlgorithmPolicy(new AlgorithmPolicy() {

			@Override
			public void checkSignatureAlgorithm(String signatureAlgorithm,
					Date validationDate) throws SignatureException {
				// allow all
			}
		});

		// next is kind of a default trust linked pattern.
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(
				networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		// operate
		trustValidator.isTrusted(certificateChain);
	}
}