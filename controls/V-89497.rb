control "V-89497" do
  title "The SLES for vRealize must protect audit information from unauthorized
modification."
  desc  "If audit information were to become compromised, then forensic
analysis and discovery of the true source of potentially malicious system
activity is impossible to achieve.

    To ensure the veracity of audit information, the operating system must
protect audit information from unauthorized modification.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit information system
activity.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000058-GPOS-00028"
  tag "gid": "V-89497"
  tag "rid": "SV-100147r1_rule"
  tag "stig_id": "VRAU-SL-000160"
  tag "fix_id": "F-96239r1_fix"
  tag "cci": ["CCI-000163"]
  tag "nist": ["AU-9", "Rev_4"]
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
  tag "check": "Verify that the system audit logs with the following command:

# (audit_log_file=$(grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//)
&& if [ -f \"${audit_log_file}\" ] ; then printf \"Log(s) found in
\"${audit_log_file%/*}\":\
\"; ls -l ${audit_log_file%/*}; else printf \"audit log file(s) not found\
\"; fi)

If any audit log file has a mode more permissive than \"0640\", this is a
finding."
  tag "fix": "Change the mode of the audit log file(s):

# chmod 0640 <audit log file>"

describe file('/var/log/audit/audit.log') do
  it { should_not be_more_permissive_than('0640') }
end

end

