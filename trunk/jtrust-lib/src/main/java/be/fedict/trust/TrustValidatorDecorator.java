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

package be.fedict.trust;

import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.ocsp.OnlineOcspRepository;

/**
 * Trust Validator Decorator. This class helps to configure trust validators.
 * 
 * @author Frank Cornelis
 * 
 */
public class TrustValidatorDecorator {

	private final NetworkConfig networkConfig;

	/**
	 * Main constructor.
	 * 
	 * @param networkConfig
	 *            the network configuration to be used. Can be <code>null</code>
	 *            .
	 */
	public TrustValidatorDecorator(NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	/**
	 * Adds a default trust linker configuration to a given trust validator.
	 * 
	 * @param trustValidator
	 *            the trust validator to be configured.
	 * @param externalTrustLinker
	 *            optional additional trust linker.
	 */
	public void addDefaultTrustLinkerConfig(TrustValidator trustValidator,
			TrustLinker externalTrustLinker) {
		addDefaultTrustLinkerConfig(trustValidator, externalTrustLinker, false);
	}

	/**
	 * Adds a default trust linker configuration to a given trust validator.
	 * 
	 * @param trustValidator
	 *            the trust validator to be configured.
	 * @param externalTrustLinker
	 *            optional additional trust linker.
	 * @param noOcsp
	 *            set to <code>true</code> to avoid OCSP validation.
	 */
	public void addDefaultTrustLinkerConfig(TrustValidator trustValidator,
			TrustLinker externalTrustLinker, boolean noOcsp) {
		trustValidator.addTrustLinker(new PublicKeyTrustLinker());

		OnlineOcspRepository ocspRepository = new OnlineOcspRepository(
				this.networkConfig);

		OnlineCrlRepository crlRepository = new OnlineCrlRepository(
				this.networkConfig);
		CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(
				crlRepository);

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		if (null != externalTrustLinker) {
			fallbackTrustLinker.addTrustLinker(externalTrustLinker);
		}
		if (false == noOcsp) {
			fallbackTrustLinker.addTrustLinker(new OcspTrustLinker(
					ocspRepository));
		}
		fallbackTrustLinker.addTrustLinker(new CrlTrustLinker(
				cachedCrlRepository));

		trustValidator.addTrustLinker(fallbackTrustLinker);
	}

	/**
	 * Adds a default trust linker configuration to a given trust validator.
	 * 
	 * @param trustValidator
	 *            the trust validator to be configured.
	 */
	public void addDefaultTrustLinkerConfig(TrustValidator trustValidator) {
		addDefaultTrustLinkerConfig(trustValidator, null);
	}
}
