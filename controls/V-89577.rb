control "V-89577" do
  title "SLES for vRealize must enforce 24 hours/1 day as the minimum password
lifetime."
  desc  "Enforcing a minimum password lifetime helps to prevent repeated
password changes to defeat the password reuse or history enforcement
requirement. If users are allowed to immediately and continually change their
password, then the password could be repeatedly changed in a short period of
time to defeat the organization's policy regarding password reuse."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000075-GPOS-00043"
  tag "gid": "V-89577"
  tag "rid": "SV-100227r1_rule"
  tag "stig_id": "VRAU-SL-000380"
  tag "fix_id": "F-96319r1_fix"
  tag "cci": ["CCI-000198"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
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
  tag "check": "To check that the SLES for vRealize enforces 24 hours/1 day as
the minimum password age, run the following command:

# grep PASS_MIN_DAYS /etc/login.defs | grep -v '#'

The DoD requirement is \"1\".

If \"PASS_MIN_DAYS\" is not set to the required value, this is a finding."
  tag "fix": "To configure the SLES for vRealize to enforce 24 hours/1 day as
the minimum password age, edit the file \"/etc/login.defs\" with the following
command:

# sed -i \"/^[^#]*PASS_MIN_DAYS/ c\\PASS_MIN_DAYS 1\" /etc/login.defs"
end

