control "V-89863" do
  title "The SLES for vRealize must, at a minimum, off-load audit information
on interconnected systems in real time and off-load standalone systems weekly."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000479-GPOS-00224"
  tag "gid": "V-89863"
  tag "rid": "SV-100513r1_rule"
  tag "stig_id": "VRAU-SL-001495"
  tag "fix_id": "F-96605r2_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
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
  tag "check": "Check the \"syslog\" configuration file for remote syslog
servers:

# cat /etc/syslog-ng/syslog-ng.conf | grep logserver

If no line is returned, or \"logserver\" is commented out, this is a finding."
  tag "fix": "Edit the syslog configuration file and add an appropriate remote
syslog server:

In the /etc/syslog-ng/syslog-ng.conf file, the remote logging entries must be
uncommented and the IP address must be modified to point to the remote syslog
server:

#
# Enable this and adopt IP to send log messages to a log server.
#
destination logserver { udp(\"10.10.10.10\" port(514)); };
log { source(src); destination(logserver); };"
end

