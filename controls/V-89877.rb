control "V-89877" do
  title "The SLES for vRealize must be configured in accordance with the
security configuration settings based on DoD security configuration or
implementation guidance, including STIGs, NSA configuration guides, CTOs, and
DTMs."
  desc  "Configuring the operating system to implement organization-wide
security implementation guides and security checklists ensures compliance with
federal standards and establishes a common security baseline across DoD that
reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed in
hardware, software, or firmware components of the system that affect the
security posture and/or functionality of the system. Security-related
parameters are those parameters impacting the security state of the system,
including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example: registry
settings; account, file, directory permission settings; and settings for
functions, ports, protocols, services, and remote connections.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-89877"
  tag "rid": "SV-100527r1_rule"
  tag "stig_id": "VRAU-SL-001530"
  tag "fix_id": "F-96619r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Verify the SLES for vRealize is configured in accordance with
the security configuration settings based on DoD security configuration or
implementation guidance, including STIGs, NSA configuration guides, CTOs, and
DTMs.

If it is not, this is a finding."
  tag "fix": "Configure the SLES for vRealize in accordance with the security
configuration settings based on DoD security configuration or implementation
guidance, including STIGs, NSA configuration guides, CTOs, and DTMs."

describe "Manual test" do
  skip "This control must be reviewed manually"
end

end

