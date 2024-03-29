control "V-89563" do
  title "The SLES for vRealize must enforce password complexity by requiring
that at least one upper-case character be used."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000069-GPOS-00037"
  tag "gid": "V-89563"
  tag "rid": "SV-100213r1_rule"
  tag "stig_id": "VRAU-SL-000340"
  tag "fix_id": "F-96305r1_fix"
  tag "cci": ["CCI-000192"]
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
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
  tag "check": "Check the SLES for vRealize enforces password complexity by
requiring that at least one upper-case character be used by using the following
command:

# grep ucredit /etc/pam.d/common-password-vmware.local

If \"ucredit\" is not set to \"-1\" or not at all, this is a finding.

Expected Result:
password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=14 difok=4 retry=3"
  tag "fix": "If \"ucredit\" was not set at all in
/etc/pam.d/common-password-vmware.local then run the following command:

# sed -i '/pam_cracklib.so/ s/$/ ucredit=-1/'
/etc/pam.d/common-password-vmware.local

If \"ucredit\" was set incorrectly then run the following command to set it to
\"-1\":

# sed -i '/pam_cracklib.so/ s/ucredit=../ucredit=-1/'
/etc/pam.d/common-password-vmware.local"

describe file('/etc/pam.d/common-password-vmware.local') do
  its('content') {should match %r{ucredit=-1} }
end

end

