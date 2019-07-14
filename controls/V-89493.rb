control "V-89493" do
  title "The SLES for vRealize must protect audit information from unauthorized
read access - ownership."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit operating system activity.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000057-GPOS-00027"
  tag "gid": "V-89493"
  tag "rid": "SV-100143r1_rule"
  tag "stig_id": "VRAU-SL-000150"
  tag "fix_id": "F-96235r1_fix"
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
  tag "check": "Verify that the system audit logs are owned by \"root\":

# (audit_log_file=$(grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//)
&& if [ -f \"${audit_log_file}\" ] ; then printf \"Log(s) found in
\"${audit_log_file%/*}\":\
\"; ls -l ${audit_log_file%/*}; else printf \"audit log file(s) not found\
\"; fi)

If any audit log file is not owned by \"root\", this is a finding."
  tag "fix": "Change the ownership of the audit log file(s).

Procedure:
# chown root <audit log file>

# chown root /var/log/audit/audit.log"
end

