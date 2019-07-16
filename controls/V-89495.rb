control "V-89495" do
  title "The SLES for vRealize must protect audit information from unauthorized
read access - group-ownership."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit operating system activity.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000057-GPOS-00027"
  tag "gid": "V-89495"
  tag "rid": "SV-100145r1_rule"
  tag "stig_id": "VRAU-SL-000155"
  tag "fix_id": "F-96237r1_fix"
  tag "cci": ["CCI-000162"]
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
  tag "check": "Verify that the system audit logs are group-owned by \"root\":

# (audit_log_file=$(grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//)
&& if [ -f \"${audit_log_file}\" ] ; then printf \"Log(s) found in
\"${audit_log_file%/*}\":\
\"; ls -l ${audit_log_file%/*}; else printf \"audit log file(s) not found\
\"; fi)

If any audit log file is not group-owned by \"root\" or \"admin\", this is a
finding."
  tag "fix": "Change the group-ownership of the audit log file(s).

Procedure:
# chgrp root <audit log file>

# chgrp root /var/log/audit/audit.log"

describe.one do
  #check if group is root or admin
  describe file('/var/log/audit/audit.log') do
    its('group') { should eq 'root' }
  end
  describe file('/var/log/audit/audit.log') do
    its('group') { should eq 'admin' }
  end
end

end

