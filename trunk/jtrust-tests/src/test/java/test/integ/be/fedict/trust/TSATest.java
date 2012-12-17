/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
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
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import be.fedict.trust.constraints.TSACertificateConstraint;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.trust.MemoryCertificateRepository;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;

public class TSATest {

	private static final Log LOG = LogFactory.getLog(TSATest.class);

	private static final String TSA_LOCATION = "http://tsa.belgium.be/connect";

	@BeforeClass
	public static void setUp() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testTSAViaJTrust() throws Exception {

		// setup
		TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
		requestGen.setCertReq(true);
		TimeStampRequest request = requestGen.generate(TSPAlgorithms.SHA1,
				new byte[20], BigInteger.valueOf(100));
		byte[] requestData = request.getEncoded();

		HttpClient httpClient = new HttpClient();
		httpClient.getHostConfiguration().setProxy("proxy.yourict.net", 8080);
		PostMethod postMethod = new PostMethod(TSA_LOCATION);
		postMethod.setRequestEntity(new ByteArrayRequestEntity(requestData,
				"application/timestamp-query"));

		// operate
		long t0 = System.currentTimeMillis();
		int statusCode = httpClient.executeMethod(postMethod);
		long t1 = System.currentTimeMillis();
		LOG.debug("dt TSP: " + (t1 - t0) + " ms");
		if (statusCode != HttpStatus.SC_OK) {
			LOG.error("Error contacting TSP server " + TSA_LOCATION);
			throw new Exception("Error contacting TSP server " + TSA_LOCATION);
		}

		TimeStampResponse tspResponse = new TimeStampResponse(
				postMethod.getResponseBodyAsStream());
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
		NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net",
				8080);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(
				networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certificateChain);
	}

    @Test
    public void testTSA2013() throws Exception {
         LOG.debug("test TSA 2013");
        InputStream inputStream = TSATest.class.getResourceAsStream("/Fedict-2013.txt");
        byte[] data = IOUtils.toByteArray(inputStream);
        byte[] derData = Base64.decode(data);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<X509Certificate> certificates = (Collection<X509Certificate>) certificateFactory.generateCertificates(new ByteArrayInputStream(derData));
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
        NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net",
                8080);
        TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(
                networkConfig);
        trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

        trustValidator.addCertificateConstrain(new TSACertificateConstraint());

        trustValidator.isTrusted(certificateChain);
    }
}
