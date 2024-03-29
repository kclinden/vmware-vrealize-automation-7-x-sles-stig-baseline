control "V-89569" do
  title "The SLES for vRealize must enforce password complexity by requiring
that at least one numeric character be used."
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
  tag "gtitle": "SRG-OS-000071-GPOS-00039"
  tag "gid": "V-89569"
  tag "rid": "SV-100219r1_rule"
  tag "stig_id": "VRAU-SL-000355"
  tag "fix_id": "F-96311r1_fix"
  tag "cci": ["CCI-000194"]
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
  tag "check": "Check that the SLES for vRealize enforces password complexity
by requiring that at least one numeric character be used by running the
following command:

# grep dcredit /etc/pam.d/common-password-vmware.local

If \"dcredit\" is not set to \"-1\" or is not set at all, this is a finding.

Expected Result:
password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=14 difok=4 retry=3"
  tag "fix": "If \"dcredit\" was not set at all in
/etc/pam.d/common-password-vmware.local, run the following command:

# sed -i '/pam_cracklib.so/ s/$/ dcredit=-1/'
/etc/pam.d/common-password-vmware.local

If \"dcredit\" was set incorrectly, run the following command:

# sed -i '/pam_cracklib.so/ s/dcredit=../dcredit=-1/'
/etc/pam.d/common-password-vmware.local"

describe file('/etc/pam.d/common-password-vmware.local') do
  its('content') {should match %r{dcredit=-1} }
end

end

