// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"testing"

	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func padbImpl(t *testing.T) (*PolicyAuthorityDatabaseImpl, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnPolicy)
	test.AssertNotError(t, err, "Could not construct dbMap")

	padb, err := NewPolicyAuthorityDatabaseImpl(dbMap)
	test.AssertNotError(t, err, "Couldn't create PADB")

	cleanUp := test.ResetPolicyTestDatabase(t)

	return padb, cleanUp
}

func TestLoadAndDumpRules(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	load := RuleSet{
		Blacklist: []BlacklistRule{
			BlacklistRule{
				Host: "bad.com",
			},
		},
	}
	err := p.LoadRules(load)
	test.AssertNotError(t, err, "Couldn't load rules")

	dumped, err := p.DumpRules()
	test.AssertNotError(t, err, "Couldn't dump rules")
	test.AssertEquals(t, len(dumped.Blacklist), 1)

	test.AssertEquals(t, dumped.Blacklist[0], load.Blacklist[0])
}

func TestBlacklist(t *testing.T) {
	p, cleanup := padbImpl(t)
	defer cleanup()

	err := p.LoadRules(RuleSet{
		Blacklist: []BlacklistRule{
			BlacklistRule{
				Host: "bad.com",
			},
		},
	})
	test.AssertNotError(t, err, "Couldn't load rules")

	err = p.CheckHostLists("bad.com")
	test.AssertError(t, err, "Hostname should be blacklisted")
	err = p.CheckHostLists("still.bad.com")
	test.AssertError(t, err, "Hostname should be blacklisted")
	err = p.CheckHostLists("badminton.com")
	test.AssertNotError(t, err, "Hostname shouldn't be blacklisted")
	// Not blacklisted
	err = p.CheckHostLists("good.com")
	test.AssertNotError(t, err, "Hostname shouldn't be blacklisted")
}
