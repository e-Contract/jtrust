/*
 * Java Trust Project.
 * Copyright (C) 2015-2020 e-Contract.be BV.
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
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.OnlineCrlRepository;

public class CachedCrlRepositoryTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(CachedCrlRepositoryTest.class);

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testCachingBehavior() throws Exception {
		// setup
		OnlineCrlRepository onlineCrlRepository = new OnlineCrlRepository();
		CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(onlineCrlRepository);

		Date validationDate = new Date();

		// operate
		long t0 = System.currentTimeMillis();
		cachedCrlRepository.findCrl(new URI("http://crl.eid.belgium.be/belgium3.crl"), null, validationDate);
		long t1 = System.currentTimeMillis();
		LOGGER.debug("dt: {} ms", (t1 - t0));
		LOGGER.debug("---------------------------------------------");
		t0 = System.currentTimeMillis();
		cachedCrlRepository.findCrl(new URI("http://crl.eid.belgium.be/belgium3.crl"), null, validationDate);
		t1 = System.currentTimeMillis();
		LOGGER.debug("dt: {} ms", (t1 - t0));
	}
}
