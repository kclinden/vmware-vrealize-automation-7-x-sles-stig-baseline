control "V-89871" do
  title "The SLES for vRealize must enforce a delay of at least 4 seconds
between logon prompts following a failed logon attempt."
  desc  "Limiting the number of logon attempts over a certain time interval
reduces the chances that an unauthorized user may gain access to an account."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00226"
  tag "gid": "V-89871"
  tag "rid": "SV-100521r1_rule"
  tag "stig_id": "VRAU-SL-001515"
  tag "fix_id": "F-96613r1_fix"
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
  tag "check": "Check the value of the \"FAIL_DELAY\" variable and the ability
to use it:

# grep FAIL_DELAY /etc/login.defs

The following result should be displayed:

FAIL_DELAY 4

If the value does not exist, or is less than \"4\", this is a finding.

Check for the use of \"pam_faildelay\":

# grep pam_faildelay /etc/pam.d/common-auth*

The following result should be displayed:

/etc/pam.d/common-auth:auth optional pam_faildelay.so

If the \"pam_faildelay.so\" module is not listed or is commented out, this is a
finding."
  tag "fix": "Add the \"pam_faildelay\" module and set the \"FAIL_DELAY\"
variable.

Edit \"/etc/login.defs\" and set the value of the \"FAIL_DELAY\" variable to
\"4\" or more.

Edit \"/etc/pam.d/common-auth\" and add a \"pam_faildelay\" entry if one does
not exist, such as:

auth optional pam_faildelay.so"

describe login_defs do
  its('FAIL_DELAY') { should cmp '4' }
end

describe file('/etc/pam.d/common-auth') do
  its('content'){should match %r{auth\toptional\tpam_faildelay.so}}
end



end

