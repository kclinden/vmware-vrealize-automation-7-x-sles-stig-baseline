control "V-89875" do
  title "The SLES for vRealize must enforce a delay of at least 4 seconds
between logon prompts following a failed logon attempt."
  desc  "Limiting the number of logon attempts over a certain time interval
reduces the chances that an unauthorized user may gain access to an account."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00226"
  tag "gid": "V-89875"
  tag "rid": "SV-100525r1_rule"
  tag "stig_id": "VRAU-SL-001525"
  tag "fix_id": "F-96617r2_fix"
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
  tag "check": "Verify the SLES for vRealize enforces a delay of at least \"4\"
seconds between logon prompts following a failed logon attempt.

Verify the use of the \"pam_faildelay\" module.

# grep pam_faildelay /etc/pam.d/common-auth*

The typical configuration looks something like this:

#delay is in micro seconds
auth    required    pam_faildelay.so    delay=4000000

If the line is not present, this is a finding."
  tag "fix": "Configure the SLES for vRealize to enforce a delay of at least
\"4\" seconds between logon prompts following a failed logon attempt with the
following command:

# sed -i \"/^[^#]*pam_faildelay.so/ c\\auth required pam_faildelay.so delay=4000000\" /etc/pam.d/common-auth-vmware.local"

describe pam('/etc/pam.d/common-auth-vmware.local') do
  its('lines') { should match_pam_rule('auth required pam_faildelay.so delay=4000000')}
end

end

