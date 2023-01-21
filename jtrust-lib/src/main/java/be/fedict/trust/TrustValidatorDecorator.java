/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
 * Copyright (C) 2014-2023 e-Contract.be BV.
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
import be.fedict.trust.crl.CrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.ext.CriticalExtensionTrustLinker;
import be.fedict.trust.linker.AlwaysTrustTrustLinker;
import be.fedict.trust.linker.FallbackTrustLinker;
import be.fedict.trust.linker.PublicKeyTrustLinker;
import be.fedict.trust.linker.TrustLinker;
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
	 * @param networkConfig the network configuration to be used. Can be
	 *                      <code>null</code> .
	 */
	public TrustValidatorDecorator(NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	/**
	 * Convenience constructor.
	 */
	public TrustValidatorDecorator() {
		this(null);
	}

	/**
	 * Adds a default trust linker configuration to a given trust validator.
	 * 
	 * @param trustValidator      the trust validator to be configured.
	 * @param externalTrustLinker optional additional trust linker.
	 */
	public void addDefaultTrustLinkerConfig(TrustValidator trustValidator, TrustLinker externalTrustLinker) {
		addDefaultTrustLinkerConfig(trustValidator, externalTrustLinker, false);
	}

	/**
	 * Adds a default trust linker configuration to a given trust validator.
	 * 
	 * @param trustValidator      the trust validator to be configured.
	 * @param externalTrustLinker optional additional trust linker.
	 * @param noOcsp              set to <code>true</code> to avoid OCSP validation.
	 */
	public void addDefaultTrustLinkerConfig(TrustValidator trustValidator, TrustLinker externalTrustLinker,
			boolean noOcsp) {
		addDefaultTrustLinkerConfig(trustValidator, externalTrustLinker, noOcsp, null);
	}

	/**
	 * Adds a default trust linker configuration to a given trust validator.
	 * 
	 * @param trustValidator      the trust validator to be configured.
	 * @param externalTrustLinker optional additional trust linker.
	 * @param noOcsp              set to <code>true</code> to avoid OCSP validation.
	 * @param crlRepository       the optional CRL repository to use.
	 */
	public void addDefaultTrustLinkerConfig(TrustValidator trustValidator, TrustLinker externalTrustLinker,
			boolean noOcsp, CrlRepository crlRepository) {
		trustValidator.addTrustLinker(new PublicKeyTrustLinker());
		trustValidator.addTrustLinker(new CriticalExtensionTrustLinker());

		OnlineOcspRepository ocspRepository = new OnlineOcspRepository(this.networkConfig);

		if (null == crlRepository) {
			OnlineCrlRepository onlineCrlRepository = new OnlineCrlRepository(this.networkConfig);
			crlRepository = new CachedCrlRepository(onlineCrlRepository);
		}

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		if (null != externalTrustLinker) {
			fallbackTrustLinker.addTrustLinker(externalTrustLinker);
		}
		if (false == noOcsp) {
			fallbackTrustLinker.addTrustLinker(new OcspTrustLinker(ocspRepository));
		}
		fallbackTrustLinker.addTrustLinker(new CrlTrustLinker(crlRepository));

		trustValidator.addTrustLinker(fallbackTrustLinker);
	}

	/**
	 * Adds a default trust linker configuration to a given trust validator.
	 * 
	 * @param trustValidator the trust validator to be configured.
	 */
	public void addDefaultTrustLinkerConfig(TrustValidator trustValidator) {
		addDefaultTrustLinkerConfig(trustValidator, null);
	}

	/**
	 * Adds a trust linker configuration to be used to validate already expired
	 * certificates. Please notice that this configuration will not perform any
	 * verification on the revocation status of the certificates.
	 * 
	 * @param trustValidator the trust validator to be configured.
	 */
	public void addTrustLinkerConfigWithoutRevocationStatus(TrustValidator trustValidator) {
		trustValidator.addTrustLinker(new PublicKeyTrustLinker(true));
		trustValidator.addTrustLinker(new AlwaysTrustTrustLinker());
		trustValidator.addTrustLinker(new CriticalExtensionTrustLinker());
	}
}
