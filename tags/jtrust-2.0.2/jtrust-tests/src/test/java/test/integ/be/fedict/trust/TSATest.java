/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
 * Copyright (C) 2013 e-Contract.be BVBA.
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
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.constraints.TSACertificateConstraint;
import be.fedict.trust.repository.CertificateRepository;
import be.fedict.trust.repository.MemoryCertificateRepository;

public class TSATest {

	private static final Log LOG = LogFactory.getLog(TSATest.class);

	private static final String TSA_LOCATION = "http://tsa.belgium.be/connect";

	@BeforeClass
	public static void setUp() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testTSAViaJTrust() throws Exception {
		testTimestampServerTrust(TSA_LOCATION);
	}

	@Test
	public void testStarfieldTechTrust() throws Exception {
		testTimestampServerTrust("http://tsa.starfieldtech.com");
	}

	private void testTimestampServerTrust(String tsaLocation) throws Exception {
		// setup
		TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
		requestGen.setCertReq(true);
		TimeStampRequest request = requestGen.generate(TSPAlgorithms.SHA1,
				new byte[20], BigInteger.valueOf(100));
		byte[] requestData = request.getEncoded();

		DefaultHttpClient httpClient = new DefaultHttpClient();
		// HttpHost proxy = new HttpHost("proxy.yourict.net", 8080);
		// httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY,
		// proxy);
		HttpPost postMethod = new HttpPost(tsaLocation);
		ContentType contentType = ContentType
				.create("application/timestamp-query");
		HttpEntity requestEntity = new ByteArrayEntity(requestData, contentType);
		postMethod.addHeader("User-Agent", "jTrust TSP Client");
		postMethod.setEntity(requestEntity);

		// operate
		long t0 = System.currentTimeMillis();
		HttpResponse httpResponse = httpClient.execute(postMethod);
		StatusLine statusLine = httpResponse.getStatusLine();
		int statusCode = statusLine.getStatusCode();
		long t1 = System.currentTimeMillis();
		LOG.debug("dt TSP: " + (t1 - t0) + " ms");
		if (statusCode != HttpURLConnection.HTTP_OK) {
			LOG.error("Error contacting TSP server " + TSA_LOCATION);
			throw new Exception("Error contacting TSP server " + TSA_LOCATION);
		}

		HttpEntity httpEntity = httpResponse.getEntity();
		TimeStampResponse tspResponse = new TimeStampResponse(
				httpEntity.getContent());
		postMethod.releaseConnection();

		CertStore certStore = tspResponse.getTimeStampToken()
				.getCertificatesAndCRLs("Collection", "BC");

		Collection<? extends Certificate> certificates = certStore
				.getCertificates(null);
		for (Certificate certificate : certificates) {
			LOG.debug("certificate: " + certificate.toString());
		}

		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		for (Certificate certificate : certificates) {
			certificateChain.add(0, (X509Certificate) certificate);
		}

		for (X509Certificate cert : certificateChain) {
			LOG.debug("certificate subject: " + cert.getSubjectX500Principal());
			LOG.debug("certificate issuer: " + cert.getIssuerX500Principal());
		}

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate gsCert = (X509Certificate) certificateFactory
				.generateCertificate(TSATest.class
						.getResourceAsStream("/be/fedict/trust/roots/globalsign-be.crt"));
		certificateRepository.addTrustPoint(gsCert);
		TrustValidator trustValidator = new TrustValidator(
				certificateRepository);
		// NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net",
		// 8080);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(
				null);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certificateChain);
	}

	@Test
	public void testTSA2013() throws Exception {
		LOG.debug("test TSA 2013");
		InputStream inputStream = TSATest.class
				.getResourceAsStream("/Fedict-2013.txt");
		byte[] data = IOUtils.toByteArray(inputStream);
		byte[] derData = Base64.decode(data);
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		Collection<X509Certificate> certificates = (Collection<X509Certificate>) certificateFactory
				.generateCertificates(new ByteArrayInputStream(derData));
		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		for (X509Certificate certificate : certificates) {
			certificateChain.add(0, certificate);
		}

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		X509Certificate gsCert = (X509Certificate) certificateFactory
				.generateCertificate(TSATest.class
						.getResourceAsStream("/be/fedict/trust/roots/globalsign-be.crt"));
		certificateRepository.addTrustPoint(gsCert);
		TrustValidator trustValidator = new TrustValidator(
				certificateRepository);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(
				null);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.addCertificateConstrain(new TSACertificateConstraint());

		trustValidator.isTrusted(certificateChain);
	}

	private X509Certificate loadCertificate(String pemResourceName)
			throws IOException, CertificateException {
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		InputStream tsaCertInputStream = TSATest.class
				.getResourceAsStream(pemResourceName);
		PemReader pemReader = new PemReader(new InputStreamReader(
				tsaCertInputStream));
		PemObject pemObject = pemReader.readPemObject();
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(pemObject
						.getContent()));
		pemReader.close();
		return certificate;
	}

	@Test
	public void testTSA2014() throws Exception {
		LOG.debug("test TSA 2014");
		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();

		certificateChain
				.add(loadCertificate("/tsa2014/TimeStampingAuthority.pem"));
		certificateChain.add(loadCertificate("/tsa2014/Belgium ROOT CA 2.pem"));
		certificateChain
				.add(loadCertificate("/tsa2014/Cybertrust Global Root.pem"));
		certificateChain
				.add(loadCertificate("/tsa2014/Baltimore Cybertrust Root.pem"));

		CertificateRepository tsaCertificateRepository = BelgianTrustValidatorFactory
				.createTSACertificateRepository();
		TrustValidator trustValidator = new TrustValidator(
				tsaCertificateRepository);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.addCertificateConstrain(new TSACertificateConstraint());

		trustValidator.isTrusted(certificateChain);
	}

	@Test
	public void testReadTSA2014() throws Exception {
		X509Certificate tsaCert = loadCertificate("/tsa2014/TimeStampingAuthority.pem");
		LOG.debug("TSA cert: " + tsaCert);
		File tmpFile = File.createTempFile("tsa-2014-", ".der");
		FileUtils.writeByteArrayToFile(tmpFile, tsaCert.getEncoded());
		LOG.debug("TSA cert file: " + tmpFile.getAbsolutePath());
	}

	@Test
	public void testTSA2014_2() throws Exception {
		LOG.debug("test TSA 2014");
		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();

		certificateChain
				.add(loadCertificate("/tsa2014/TimeStampingAuthority.pem"));
		certificateChain.add(loadCertificate("/tsa2014/Belgium ROOT CA 2.pem"));
		certificateChain
				.add(loadCertificate("/tsa2014/Cybertrust Global Root.pem"));
		certificateChain
				.add(loadCertificate("/tsa2014/Baltimore Cybertrust Root.pem"));

		TrustValidator trustValidator = BelgianTrustValidatorFactory
				.createTSATrustValidator(null);

		trustValidator.isTrusted(certificateChain);
	}
}
