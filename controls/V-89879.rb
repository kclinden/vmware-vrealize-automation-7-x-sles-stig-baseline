control "V-89879" do
  title "The SLES for vRealize must define default permissions for all
authenticated users in such a way that the user can only read and modify their
own files."
  desc  "Setting the most restrictive default permissions ensures that when new
accounts are created they do not have unnecessary access."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00228"
  tag "gid": "V-89879"
  tag "rid": "SV-100529r1_rule"
  tag "stig_id": "VRAU-SL-001535"
  tag "fix_id": "F-96621r1_fix"
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
  tag "check": "Check for the configured \"umask\" value in \"login.defs\" with
the following command:

# grep UMASK /etc/login.defs

If the default \"umask\" is not \"077\", this a finding.

Note: If the default umask is \"000\" or allows for the creation of
world-writable files this becomes a Severity Code I finding."
  tag "fix": "To configure the correct UMASK setting run the following command:

# sed -i \"/^[^#]*UMASK/ c\\UMASK 077\" /etc/login.defs"
end

