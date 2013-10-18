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

import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import be.fedict.commons.eid.jca.BeIDProvider;
import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.linker.PublicKeyTrustLinker;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.ocsp.OnlineOcspRepository;
import be.fedict.trust.repository.CertificateRepository;

public class BelgianIdentityCardTrustValidatorTest {

	@Test
	public void testValidity() throws Exception {
		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		Certificate[] authnCertificateChain = keyStore
				.getCertificateChain("Authentication");

		Security.addProvider(new BouncyCastleProvider());

		NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net",
				8080);
		CertificateRepository certificateRepository = BelgianTrustValidatorFactory
				.createCertificateRepository();
		TrustValidator trustValidator = new TrustValidator(
				certificateRepository);

		trustValidator.addTrustLinker(new PublicKeyTrustLinker());

		// OverrideOnlineOcspRepository ocspRepository = new
		// OverrideOnlineOcspRepository(
		// networkConfig);
		OnlineOcspRepository ocspRepository = new OnlineOcspRepository(
				networkConfig);
		// ocspRepository.overrideOCSP(new URI("http://ocsp.eid.belgium.be"),
		// new URI("http://64.18.17.111"));

		OnlineCrlRepository crlRepository = new OnlineCrlRepository(
				networkConfig);
		CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(
				crlRepository);

		trustValidator.addTrustLinker(new OcspTrustLinker(ocspRepository));
		trustValidator.addTrustLinker(new CrlTrustLinker(cachedCrlRepository));

		trustValidator.isTrusted(authnCertificateChain);
	}
}
