/*
 * Java Trust Project.
 * Copyright (C) 2021 e-Contract.be BV.
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

package be.fedict.trust.test;

public class BasicOCSPFailBehavior implements OCSPFailBehavior {

	private boolean failing;

	private Clock failingClock;

	@Override
	public boolean fail() {
		return this.failing;
	}

	@Override
	public Clock getFailingClock() {
		return this.failingClock;
	}

	/**
	 * Sets whether the corresponding failable endpoint should fail or not.
	 * 
	 * @param failing
	 */
	public void setFailing(boolean failing) {
		this.failing = failing;
	}

	/**
	 * Sets a failing clock for the OCSP endpoint.
	 * 
	 * @param failingClock
	 */
	public void setFailingClock(Clock failingClock) {
		this.failingClock = failingClock;
	}
}
