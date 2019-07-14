control "V-89501" do
  title "The SLES for vRealize must protect audit information from unauthorized
deletion - log directories."
  desc  "If audit information were to become compromised, then forensic
analysis and discovery of the true source of potentially malicious system
activity is impossible to achieve.

    To ensure the veracity of audit information, the operating system must
protect audit information from unauthorized deletion. This requirement can be
achieved through multiple methods, which will depend upon system architecture
and design.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit information system
activity.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000059-GPOS-00029"
  tag "gid": "V-89501"
  tag "rid": "SV-100151r1_rule"
  tag "stig_id": "VRAU-SL-000170"
  tag "fix_id": "F-96243r1_fix"
  tag "cci": ["CCI-000164"]
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
  tag "check": "Run the following command to check the mode of the system audit
directories:

# grep \"^log_file\" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs
stat -c %a:%n

Audit directories must be mode \"0700\".

If any are more permissive, this is a finding."
  tag "fix": "Change the mode of the audit log directories with the following
command:

# chmod 700 <audit log directory>"
end

