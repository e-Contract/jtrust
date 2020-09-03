/*
 * Java Trust Project.
 * Copyright (C) 2011 Frank Cornelis.
 * Copyright (C) 2016-2020 e-Contract.be BV.
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

import java.io.File;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.commons.eid.jca.BeIDProvider;
import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.constraints.QCStatementsCertificateConstraint;
import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.linker.PublicKeyTrustLinker;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.ocsp.OnlineOcspRepository;
import be.fedict.trust.repository.CertificateRepository;
import be.fedict.trust.repository.MemoryCertificateRepository;

public class BelgianIdentityCardTrustValidatorTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(BelgianIdentityCardTrustValidatorTest.class);

	@Test
	public void testValidity() throws Exception {
		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		Certificate[] authnCertificateChain = keyStore.getCertificateChain("Authentication");

		LOGGER.debug("authn cert: {}", authnCertificateChain[0]);

		Security.addProvider(new BouncyCastleProvider());

		NetworkConfig networkConfig = null;
		CertificateRepository certificateRepository = BelgianTrustValidatorFactory.createCertificateRepository();
		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		trustValidator.addTrustLinker(new PublicKeyTrustLinker());

		OnlineOcspRepository ocspRepository = new OnlineOcspRepository(networkConfig);

		OnlineCrlRepository crlRepository = new OnlineCrlRepository(networkConfig);
		CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(crlRepository);

		trustValidator.addTrustLinker(new OcspTrustLinker(ocspRepository));
		trustValidator.addTrustLinker(new CrlTrustLinker(cachedCrlRepository));

		trustValidator.isTrusted(authnCertificateChain);
	}

	@Test
	public void testValidityTrustedRoot() throws Exception {
		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		Certificate[] authnCertificateChain = keyStore.getCertificateChain("Authentication");

		LOGGER.debug("authn cert: {}", authnCertificateChain[0]);

		Security.addProvider(new BouncyCastleProvider());

		NetworkConfig networkConfig = null;
		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository.addTrustPoint((X509Certificate) authnCertificateChain[authnCertificateChain.length - 1]);
		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		trustValidator.addTrustLinker(new PublicKeyTrustLinker());

		OnlineOcspRepository ocspRepository = new OnlineOcspRepository(networkConfig);

		OnlineCrlRepository crlRepository = new OnlineCrlRepository(networkConfig);
		CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(crlRepository);

		// trustValidator.addTrustLinker(new OcspTrustLinker(ocspRepository));
		trustValidator.addTrustLinker(new CrlTrustLinker(cachedCrlRepository));

		trustValidator.isTrusted(authnCertificateChain);
	}

	@Test
	public void testValidateSignatureCertificate() throws Exception {
		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		Certificate[] certificateChain = keyStore.getCertificateChain("Signature");

		LOGGER.debug("certificate: {}", certificateChain[0]);

		Security.addProvider(new BouncyCastleProvider());

		CertificateRepository certificateRepository = BelgianTrustValidatorFactory.createCertificateRepository();
		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.addCertificateConstraint(new QCStatementsCertificateConstraint(true, true));

		trustValidator.isTrusted(certificateChain);
	}

	@Test
	public void testWriteSignatureCertificateToFile() throws Exception {
		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		Certificate[] certificateChain = keyStore.getCertificateChain("Signature");

		File tmpFile = File.createTempFile("sign-cert-", ".der");
		FileUtils.writeByteArrayToFile(tmpFile, certificateChain[0].getEncoded());
		LOGGER.debug("sign cert file: {}", tmpFile.getAbsolutePath());
	}
}
