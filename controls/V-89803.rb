control "V-89803" do
  title "The SLES for vRealize must audit all activities performed during
nonlocal maintenance and diagnostic sessions."
  desc  "If events associated with nonlocal administrative access or diagnostic
sessions are not logged, a major tool for assessing and investigating attacks
would not be available.

    This requirement addresses auditing-related issues associated with
maintenance tools used specifically for diagnostic and repair actions on
organizational information systems.

    Nonlocal maintenance and diagnostic activities are those activities
conducted by individuals communicating through a network, either an external
network (e.g., the Internet) or an internal network. Local maintenance and
diagnostic activities are those activities carried out by individuals
physically present at the information system or information system component
and not communicating across a network connection.

    This requirement applies to hardware/software diagnostic test equipment or
tools. This requirement does not cover hardware/software components that may
support information system maintenance, yet are a part of the system, for
example, the software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the
hardware and software implementing the monitoring port of an Ethernet switch.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000392-GPOS-00172"
  tag "gid": "V-89803"
  tag "rid": "SV-100453r1_rule"
  tag "stig_id": "VRAU-SL-001245"
  tag "fix_id": "F-96545r1_fix"
  tag "cci": ["CCI-002884"]
  tag "nist": ["MA-4 (1) (a)", "Rev_4"]
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
  tag "check": "Verify that all commands run by \"root\" are being audited with
the following command:

# cat /etc/audit/audit.rules | grep execve

If the following lines are not displayed, this is a finding.

-a exit,always -F arch=b64 -F euid=0 -S execve
-a exit,always -F arch=b32 -F euid=0 -S execve"
  tag "fix": "Configure the system to log all commands run by \"root\" with the
following command:

# echo \"-a exit,always -F arch=b64 -F euid=0 -S execve\" >>
/etc/audit/audit.rules

# echo \"-a exit,always -F arch=b32 -F euid=0 -S execve\" >>
/etc/audit/audit.rules

Restart the audit service:

# service auditd restart"
end

