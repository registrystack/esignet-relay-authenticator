package engine

import "github.com/mosip/esignet/internal/config"

// A missing BREG configuration must fail during provider construction, rather
// than silently selecting another identity backend.
func (ts *IdsystemFactoryTestSuite) TestBREGRequiresConfiguration() {
	ts.T().Setenv("REGISTRY_ESIGNET_CONFIG_FILE", "")
	authn, audit, err := NewIDSystemProviders(&config.AppConfig{Provider: "breg"}, nil, nil, nil, nil)
	ts.Require().Error(err)
	ts.Equal("configuration file unavailable", err.Error())
	ts.Nil(authn)
	ts.Nil(audit)
}
