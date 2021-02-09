/*
 * Java Trust Project.
 * Copyright (C) 2018-2021 e-Contract.be BV.
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

import java.time.LocalDateTime;

/**
 * Implementation of a clock that ticks from a given starting point.
 * 
 * @author Frank Cornelis
 *
 */
public class TickingClock implements Clock {

	private LocalDateTime start;

	public TickingClock(LocalDateTime start) {
		this.start = start;
	}

	@Override
	public LocalDateTime getTime() {
		LocalDateTime now = this.start;
		this.start = this.start.plusSeconds(1);
		return now;
	}

	/**
	 * Resets the clock's start time to the given value.
	 * 
	 * @param start
	 */
	public void reset(LocalDateTime start) {
		this.start = start;
	}
}
