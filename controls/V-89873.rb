control "V-89873" do
  title "The SLES for vRealize must enforce a delay of at least 4 seconds
between logon prompts following a failed logon attempt."
  desc  "Limiting the number of logon attempts over a certain time interval
reduces the chances that an unauthorized user may gain access to an account."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00226"
  tag "gid": "V-89873"
  tag "rid": "SV-100523r1_rule"
  tag "stig_id": "VRAU-SL-001520"
  tag "fix_id": "F-96615r1_fix"
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

Review the file \"/etc/login.defs\" and verify the parameter \"FAIL_DELAY\" is
a value of \"4\" or greater.

# grep FAIL_DELAY /etc/login.defs

The typical configuration looks something like this:

FAIL_DELAY    4

If the parameter \"FAIL_DELAY\" does not exists, or is less than \"4\", this is
a finding."
  tag "fix": "Configure the SLES for vRealize to enforce a delay of at least
\"4\" seconds between logon prompts following a failed logon attempt.

Set the parameter \"FAIL_DELAY\" to a value of \"4\" or greater.

Edit the file \"/etc/login.defs\". Set the parameter \"FAIL_DELAY\" to a value
of \"4\" or greater.

The typical configuration looks something like this:

FAIL_DELAY    4

Save the changes made to the file."

describe login_defs do
  its('FAIL_DELAY') { should cmp '4' }
end

end

