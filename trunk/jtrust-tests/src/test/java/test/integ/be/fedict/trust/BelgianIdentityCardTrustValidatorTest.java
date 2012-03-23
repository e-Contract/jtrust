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

import java.net.URI;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.sc.PcscEid;
import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.CertificateRepository;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.PublicKeyTrustLinker;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.ocsp.OnlineOcspRepository;

public class BelgianIdentityCardTrustValidatorTest {

	private static final Log LOG = LogFactory
			.getLog(BelgianIdentityCardTrustValidatorTest.class);

	@Test
	public void testValidity() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), new Messages(
				Locale.getDefault()));
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		List<X509Certificate> certChain = pcscEid.getAuthnCertificateChain();
		LOG.debug("cert serial nr: " + certChain.get(0).getSerialNumber());

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

		trustValidator.isTrusted(certChain);

		int count = 0;
		final int COUNT = 100;
		long t0 = System.currentTimeMillis();
		while (count < COUNT) {
			ocspRepository.findOcspResponse(new URI("http://64.18.17.111"),
					certChain.get(0), certChain.get(1));
			count++;
			LOG.debug("count: " + count);
		}
		long t1 = System.currentTimeMillis();
		long total_dt = t1 - t0;
		LOG.debug("total dt: " + total_dt);
		LOG.debug("avg dt: " + (double) total_dt / COUNT);
		LOG.debug("avg # req / sec: " + (double) COUNT * 1000 / total_dt);
	}

}
