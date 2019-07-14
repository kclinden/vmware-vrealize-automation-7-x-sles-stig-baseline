control "V-89575" do
  title "The SLES for vRealize must store only encrypted representations of
passwords."
  desc  "Passwords need to be protected at all times, and encryption is the
standard method for protecting passwords. If passwords are not encrypted, they
can be plainly read (i.e., clear text) and easily compromised."
  impact 0.7
  tag "severity": nil
  tag "gtitle": "SRG-OS-000073-GPOS-00041"
  tag "gid": "V-89575"
  tag "rid": "SV-100225r1_rule"
  tag "stig_id": "VRAU-SL-000370"
  tag "fix_id": "F-96317r1_fix"
  tag "cci": ["CCI-000196"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
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
  tag "check": "Check that the user account passwords are stored hashed using
sha512 by running the following command:

# cat /etc/default/passwd | grep CRYPT=sha512

If  \"CRYPT=sha512\" is not listed, this is a finding."
  tag "fix": "Ensure password are being encrypted with hash sha512 with the
following command:

# echo 'CRYPT=sha512'>>/etc/default/passwd"
end

