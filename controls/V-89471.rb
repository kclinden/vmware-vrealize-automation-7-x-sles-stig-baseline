control "V-89471" do
  title "The SLES for vRealize must enforce the limit of three consecutive
invalid logon attempts by a user during a 15-minute time period."
  desc  "By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000021-GPOS-00005"
  tag "gid": "V-89471"
  tag "rid": "SV-100121r1_rule"
  tag "stig_id": "VRAU-SL-000025"
  tag "fix_id": "F-96213r2_fix"
  tag "cci": ["CCI-000044"]
  tag "nist": ["AC-7 a", "Rev_4"]
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
  tag "check": "Run the following command to ensure that the operating system
enforces the limit of three consecutive invalid logon attempts by a user:

# grep pam_tally2.so /etc/pam.d/common-auth

The output should contain \"deny=3\" in the returned line.

If this is not the case, this is a finding.

Expected Result:
auth    required       pam_tally2.so deny=3 onerr=fail even_deny_root
unlock_time=86400 root_unlock_time=300"
  tag "fix": "To configure the SLES for vRealize to enforce the limit of three
consecutive invalid attempts using \"pam_tally2.so\", modify the content of the
/etc/pam.d/common-auth-vmware.local by running the following command:

# sed -i \"/^[^#]*pam_tally2.so/ c\\auth required pam_tally2.so deny=3
onerr=fail even_deny_root unlock_time=86400 root_unlock_time=300\"
/etc/pam.d/common-auth-vmware.local"

file("/etc/pam.d/common-auth").content.to_s.scan(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*deny=([0-9]+).*$/).flatten.each do |entry|
  describe entry do
    it { should cmp == 3 }
  end
end


end

