/*
 * Java Trust Project.
 * Copyright (C) 2019 e-Contract.be BVBA.
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

package be.fedict.trust.tsl;

import java.util.HashSet;
import java.util.Set;

public class TSLParserState {

	private final Set<String> parsedLocations;

	public TSLParserState() {
		this.parsedLocations = new HashSet<>();
	}

	public boolean isAlreadyParser(String location) {
		return this.parsedLocations.contains(location);
	}

	public void addParsedLocation(String location) {
		this.parsedLocations.add(location);
	}
}
