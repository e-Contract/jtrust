/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
 * Copyright (C) 2013-2022 e-Contract.be BV.
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.repository.CertificateRepository;

public class TSATest {

	private static final Logger LOGGER = LoggerFactory.getLogger(TSATest.class);

	private static final String TSA_LOCATION = "http://tsa.belgium.be/connect";

	@BeforeAll
	public static void setUp() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testTSAViaJTrust() throws Exception {
		testTimestampServerTrust(TSA_LOCATION);
	}

	private void testTimestampServerTrust(String tsaLocation) throws Exception {
		// setup
		TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
		requestGen.setCertReq(true);
		TimeStampRequest request = requestGen.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
		byte[] requestData = request.getEncoded();

		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		HttpClient httpClient = httpClientBuilder.build();
		HttpPost postMethod = new HttpPost(tsaLocation);
		ContentType contentType = ContentType.create("application/timestamp-query");
		HttpEntity requestEntity = new ByteArrayEntity(requestData, contentType);
		postMethod.addHeader("User-Agent", "jTrust TSP Client");
		postMethod.setEntity(requestEntity);

		// operate
		long t0 = System.currentTimeMillis();
		CloseableHttpResponse httpResponse = (CloseableHttpResponse) httpClient.execute(postMethod);
		int statusCode = httpResponse.getCode();
		long t1 = System.currentTimeMillis();
		LOGGER.debug("dt TSP: {} ms ", (t1 - t0));
		if (statusCode != HttpURLConnection.HTTP_OK) {
			LOGGER.error("Error contacting TSP server {}", TSA_LOCATION);
			throw new Exception("Error contacting TSP server " + TSA_LOCATION);
		}

		HttpEntity httpEntity = httpResponse.getEntity();
		TimeStampResponse tspResponse = new TimeStampResponse(httpEntity.getContent());

		TimeStampToken timeStampToken = tspResponse.getTimeStampToken();
		SignerId signerId = timeStampToken.getSID();
		Store certificatesStore = timeStampToken.getCertificates();
		Collection<X509CertificateHolder> signerCollection = certificatesStore.getMatches(signerId);

		Iterator<X509CertificateHolder> signerCollectionIterator = signerCollection.iterator();
		X509CertificateHolder signerCertificateHolder = signerCollectionIterator.next();

		// TODO: check time-stamp token signature
		List<X509Certificate> certificateChain = getCertificateChain(signerCertificateHolder, certificatesStore);

		for (X509Certificate cert : certificateChain) {
			LOGGER.debug("certificate subject: {}", cert.getSubjectX500Principal());
			LOGGER.debug("certificate issuer: {}", cert.getIssuerX500Principal());
		}

		CertificateRepository certificateRepository = BelgianTrustValidatorFactory.createTSACertificateRepository();
		TrustValidator trustValidator = new TrustValidator(certificateRepository);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(null);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certificateChain);
	}

	private static List<X509Certificate> getCertificateChain(X509CertificateHolder certificateHolder,
			Store certificatesStore) throws CertificateException, IOException {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certificateChain = new LinkedList<>();
		while (true) {
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));
			certificateChain.add(certificate);
			LOGGER.debug("certificate: {}", certificate.getSubjectX500Principal());
			IssuerSelector issuerSelector = new IssuerSelector(certificateHolder);
			Collection<X509CertificateHolder> issuerCollection = certificatesStore.getMatches(issuerSelector);
			if (issuerCollection.isEmpty()) {
				break;
			}
			certificateHolder = issuerCollection.iterator().next();
		}
		return certificateChain;
	}

	private static class IssuerSelector implements Selector {

		private final X500Name subject;

		private final boolean isSelfSigned;

		public IssuerSelector(X509CertificateHolder certificateHolder) {
			this.subject = certificateHolder.getIssuer();
			this.isSelfSigned = certificateHolder.getSubject().equals(certificateHolder.getIssuer());
		}

		@Override
		public boolean match(Object object) {
			if (false == object instanceof X509CertificateHolder) {
				return false;
			}
			X509CertificateHolder certificateHolder = (X509CertificateHolder) object;
			if (this.isSelfSigned) {
				return false;
			}
			return certificateHolder.getSubject().equals(this.subject);
		}

		@Override
		public Object clone() {
			return this;
		}
	}
}
