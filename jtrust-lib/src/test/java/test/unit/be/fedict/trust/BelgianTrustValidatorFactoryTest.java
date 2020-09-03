/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2020 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.TrustValidator;

public class BelgianTrustValidatorFactoryTest {

	@Test
	public void testCreateTrustValidator() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createTrustValidator();

		assertNotNull(trustValidator);
	}

	@Test
	public void testCreateTrustValidatorNoNetworkConfig() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createTrustValidator(null);

		assertNotNull(trustValidator);
	}

	@Test
	public void testCreateTrustValidatorNoNetworkConfigNoExternalTrustLinker() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createTrustValidator(null, null);

		assertNotNull(trustValidator);
	}

	@Test
	public void testCreateTrustValidatorNoNetworkConfigNoExternalTrustLinkerNoRepo() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createTrustValidator(null, null, null);

		assertNotNull(trustValidator);
	}

	@Test
	public void testCreateNonRepudiationTrustValidatorNoNetworkConfig() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createNonRepudiationTrustValidator(null);

		assertNotNull(trustValidator);
	}

	@Test
	public void testCreateNonRepudiationTrustValidatorNoNetworkConfigNoExternalTrustLinker() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createNonRepudiationTrustValidator(null, null);

		assertNotNull(trustValidator);
	}

	@Test
	public void testCreateNationalRegistryTrustValidatorNoNetworkConfig() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createNationalRegistryTrustValidator(null);

		assertNotNull(trustValidator);
	}

	@Test
	public void testCreateTSATrustValidator() throws Exception {
		TrustValidator trustValidator = BelgianTrustValidatorFactory.createTSATrustValidator(null, null);

		assertNotNull(trustValidator);
	}

}
