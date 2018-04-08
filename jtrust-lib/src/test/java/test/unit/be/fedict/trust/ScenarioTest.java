/*
 * Java Trust Project.
 * Copyright (C) 2018 e-Contract.be BVBA.
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

package test.unit.be.fedict.trust;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.repository.MemoryCertificateRepository;
import be.fedict.trust.test.CRLRevocationService;
import be.fedict.trust.test.CertificationAuthority;
import be.fedict.trust.test.OCSPRevocationService;
import be.fedict.trust.test.World;

public class ScenarioTest {

	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testRootCA() throws Exception {
		World world = new World();
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		world.start();

		X509Certificate rootCert = certificationAuthority.getCertificate();

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		memoryCertificateRepository.addTrustPoint(rootCert);
		TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

		trustValidator.isTrusted(Collections.singletonList(rootCert));

		world.stop();
	}

	@Test
	public void testTwoCAs() throws Exception {
		World world = new World();
		CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		rootCertificationAuthority.addRevocationService(new CRLRevocationService());
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
				rootCertificationAuthority);
		world.start();

		X509Certificate rootCert = rootCertificationAuthority.getCertificate();
		X509Certificate cert = certificationAuthority.getCertificate();
		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(cert);
		certChain.add(rootCert);

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		memoryCertificateRepository.addTrustPoint(rootCert);
		TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certChain);

		world.stop();
	}

	@Test
	public void testTwoCAsOCSP() throws Exception {
		World world = new World();
		CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		rootCertificationAuthority.addRevocationService(new OCSPRevocationService());
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
				rootCertificationAuthority);
		world.start();

		X509Certificate rootCert = rootCertificationAuthority.getCertificate();
		X509Certificate cert = certificationAuthority.getCertificate();
		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(cert);
		certChain.add(rootCert);

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		memoryCertificateRepository.addTrustPoint(rootCert);
		TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certChain);

		world.stop();
	}

	@Test
	public void testTwoCAsOCSPResponderCert() throws Exception {
		World world = new World();
		CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		rootCertificationAuthority.addRevocationService(new OCSPRevocationService(true));
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
				rootCertificationAuthority);
		world.start();

		X509Certificate rootCert = rootCertificationAuthority.getCertificate();
		X509Certificate cert = certificationAuthority.getCertificate();
		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(cert);
		certChain.add(rootCert);

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		memoryCertificateRepository.addTrustPoint(rootCert);
		TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certChain);

		world.stop();
	}
}
