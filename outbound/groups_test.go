package outbound

import (
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"testing"
)

func TestBuildGroups(t *testing.T) {
	gfwListFile := "../matcher/testdata/gfwlist.txt"
	t.Run("fallback", func(t *testing.T) {
		_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
		}})
		assert.Nil(t, err)
		t.Log(err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
		}})
		assert.Nil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
			"g2": {},
		}})
		assert.NotNil(t, err)
		t.Log(err)
	})
	t.Run("gfw", func(t *testing.T) {
		_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: "not_exists.txt"},
		}})
		assert.NotNil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: gfwListFile},
		}})
		assert.Nil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: gfwListFile},
			"g2": {GFWListFile: gfwListFile},
		}})
		assert.NotNil(t, err)
		t.Log(err)
	})
}
