package clientmgmt

func (ts *ValidateTestSuite) TestBREGClaimsAtClientRegistration() {
	for _, claim := range []string{"family_name", "person_reference"} {
		request := validCreateRequest()
		request.Claims = []string{claim}
		ts.NoError(ValidateCreate(ProfileOIDC, request, nil), claim)
		request.ClientNameLangMap = map[string]string{"eng": "Institution service"}
		ts.NoError(ValidateCreate(ProfileClient, request, nil), claim)
	}
	for _, claim := range []string{"arbitrary_registry_field", "sub", "iss", "aud"} {
		request := validCreateRequest()
		request.Claims = []string{"family_name", "person_reference", claim}
		ts.Equal("invalid_claim", errCode(ts.T(), ValidateCreate(ProfileOIDC, request, nil)), claim)
	}
}

func (ts *ValidateTestSuite) TestBREGClaimsAtClientUpdate() {
	request := validUpdateRequest()
	request.Claims = []string{"family_name", "person_reference"}
	ts.NoError(ValidateUpdate(ProfileOIDC, request))
	request.Claims = append(request.Claims, "arbitrary_registry_field")
	ts.Equal("invalid_claim", errCode(ts.T(), ValidateUpdate(ProfileOIDC, request)))
}
