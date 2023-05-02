/*
 * Java Trust Project.
 * Copyright (C) 2023 e-Contract.be BV.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Frank Cornelis
 */
public class SingleShotFailBehavior implements FailBehavior {

	private static final Logger LOGGER = LoggerFactory.getLogger(SingleShotFailBehavior.class);

	private boolean failing;

	public void singleShotFailure() {
		this.failing = true;
	}

	@Override
	public boolean fail() {
		boolean fail = this.failing;
		this.failing = false;
		if (fail) {
			LOGGER.debug("single shot failure");
		}
		return fail;
	}
}
